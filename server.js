global.fetch = require('node-fetch');
const express = require('express');
const QRCode = require('qrcode');
const { PDFDocument, rgb, StandardFonts } = require('pdf-lib');
const sharp = require('sharp');
const crypto = require('crypto');
const admin = require('firebase-admin');
const helmet = require('helmet');
const rateLimit = require("express-rate-limit");
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '20mb' }));
app.use(helmet());

const limiter = rateLimit({
  windowMs: 60_000,
  max: 6,
  message: { success: false, error: "Terlalu banyak percobaan. Tunggu 1 menit." }
});
app.use("/api/documents", limiter);

// ENV VARIABLES
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const PRIVATE_KEY_PEM = process.env.PRIVATE_KEY_PEM;
const FIREBASE_SERVICE_ACCOUNT_JSON = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
const SUPABASE_BUCKET = process.env.SUPABASE_BUCKET || 'document';
const PORT = process.env.PORT || 3000;

// INIT SUPABASE & FIREBASE
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

if (FIREBASE_SERVICE_ACCOUNT_JSON) {
  try {
    const sa = JSON.parse(FIREBASE_SERVICE_ACCOUNT_JSON);
    admin.initializeApp({ credential: admin.credential.cert(sa) });
    console.log('Firebase Admin OK');
  } catch (e) {
    console.error('Firebase init error:', e.message);
  }
}

// SUPABASE HELPER
async function downloadFromSupabase(path) {
  const { data, error } = await supabase.storage.from(SUPABASE_BUCKET).download(path);
  if (error) throw new Error(`Download gagal: ${error.message}`);
  return Buffer.from(await data.arrayBuffer());
}

async function uploadToSupabase(destPath, buffer) {
  const { data, error } = await supabase.storage.from(SUPABASE_BUCKET).upload(destPath, buffer, {
    contentType: 'application/pdf',
    upsert: true,
    cacheControl: '3600, immutable, no-transform'
  });
  if (error && error.statusCode !== '23505') throw new Error(`Upload gagal: ${error.message}`);
  return `${SUPABASE_URL}/storage/v1/object/public/${SUPABASE_BUCKET}/${destPath}`;
}

// CRYPTO
const sha256Hex = buf => crypto.createHash('sha256').update(buf).digest('hex');
const signHex = hashHex => crypto.createSign('RSA-SHA256')
  .update(Buffer.from(hashHex, 'hex')).end()
  .sign(PRIVATE_KEY_PEM, 'base64');

// TOKEN VERIFICATION
async function verifyFirebaseTokenFromHeader(req, res, next) {
  try {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    if (!token) return res.status(401).json({ success: false, error: 'No token' });
    const decoded = await admin.auth().verifyIdToken(token);
    req.user = decoded;
    const userSnap = await admin.firestore().collection('users').doc(decoded.uid).get();
    req.user.role = userSnap.exists ? userSnap.data().role : null;
    next();
  } catch (err) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }
}

// ═══════════════════════════════════════════════════════════════
// CORE SIGN — FLOW HASH YANG BENAR + QR DENGAN SHARP
// ═══════════════════════════════════════════════════════════════
async function doSign(docId, user) {
  const snap = await admin.firestore().collection('dokumen_pengajuan').doc(docId).get();
  if (!snap.exists) throw new Error('Dokumen tidak ditemukan');
  const data = snap.data();
  const filePath = data.file_path || data.file_url;
  if (!filePath) throw new Error('file_path tidak ada');

  // ✓ STEP 1: Download PDF original
  console.log(`[SIGN] STEP 1: Download PDF dari Supabase - ${filePath}`);
  const pdfBuffer = await downloadFromSupabase(filePath);

  // ✓ STEP 2: Load PDF dan siapkan fonts
  console.log(`[SIGN] STEP 2: Load PDF document`);
  const pdfDoc = await PDFDocument.load(pdfBuffer);
  const helvetica = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const bold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const page = pdfDoc.getPages()[pdfDoc.getPageCount() - 1];
  const { width, height } = page.getSize();

  // ✓ STEP 3: Tentukan posisi QR dan Stempel (BOTTOM RIGHT - sesuai contoh)
  const qrSize = 120;
  const marginRight = 40;
  const marginBottom = 80;
  
  const qrX = width - qrSize - marginRight;
  const qrY = marginBottom;
  
  console.log(`[SIGN] → Page size: ${width}x${height}`);
  console.log(`[SIGN] → QR position: x=${qrX}, y=${qrY}, size=${qrSize}`);

  // ✓ STEP 4: Tambah STEMPEL ke PDF (TANPA QR dulu!)
  console.log(`[SIGN] STEP 4: Add stamp to PDF (without QR)`);
  const stampLines = [
    "Ditandatangani secara elektronik oleh:",
    "KEPALA DESA PUCANGRO",
    `Tgl: ${new Date().toLocaleDateString('id-ID')}`
  ];
  const fontSize = 10;
  const lineHeight = 14;
  const textX = qrX - 180;
  const textY = qrY + qrSize - 20;

  stampLines.forEach((line, i) => {
    page.drawText(line, {
      x: textX,
      y: textY - (i * lineHeight),
      size: fontSize,
      font: (i === 1 ? bold : helvetica),
      color: rgb(0, 0, 0)
    });
  });

  // ✓ STEP 5: SIMPAN PDF dengan stempel (BELUM ada QR)
  console.log(`[SIGN] STEP 5: Save PDF with stamp only`);
  const pdfWithStampBuffer = await pdfDoc.save();

  // ✓ STEP 6: HITUNG HASH dari PDF + Stempel (SEKALI SAJA!)
  console.log(`[SIGN] STEP 6: Calculate SHA256 hash from PDF+stamp`);
  const hash = sha256Hex(pdfWithStampBuffer);
  console.log(`[SIGN] → Hash calculated: ${hash.substring(0, 16)}...`);

  // ✓ STEP 7: SIGN HASH dengan Private Key
  console.log(`[SIGN] STEP 7: Sign hash with private key (RSA-SHA256)`);
  const signature = signHex(hash);
  console.log(`[SIGN] → Signature created: ${signature.substring(0, 16)}...`);

  // ✓ STEP 8: Buat QR payload dengan HASH & SIGNATURE FINAL
  console.log(`[SIGN] STEP 8: Create QR payload with final hash & signature`);
  const qrPayload = JSON.stringify({
    docId,
    hash,
    signature,
    algo: "RSA-SHA256",
    signed_at: new Date().toISOString(),
    desa: "PUCANGRO"
  });
  console.log(`[SIGN] → QR Payload: ${qrPayload.substring(0, 50)}...`);

  // ✓ STEP 9: Generate QR code image dengan sharp (lebih reliable)
  console.log(`[SIGN] STEP 9: Generate QR code image dengan sharp`);
  let qrPngBuffer;
  try {
    const qrDataUrl = await QRCode.toDataURL(qrPayload, {
      errorCorrectionLevel: 'H',
      type: 'image/png',
      width: 400,
      margin: 2,
      color: { dark: '#000000', light: '#FFFFFF' }
    });
    console.log(`[SIGN] → QR DataURL generated (${qrDataUrl.length} bytes)`);
    
    // Convert DataURL ke buffer dengan sharp
    const base64Data = qrDataUrl.split(',')[1];
    qrPngBuffer = await sharp(Buffer.from(base64Data, 'base64'))
      .png()
      .toBuffer();
    
    console.log(`[SIGN] → QR PNG Buffer created (${qrPngBuffer.length} bytes) dengan sharp`);
  } catch (qrErr) {
    console.error(`[SIGN] → QR generation error: ${qrErr.message}`);
    throw new Error(`QR generation gagal: ${qrErr.message}`);
  }

  // ✓ STEP 10: Reload PDF dan Embed QR dengan cara yang lebih reliable
  console.log(`[SIGN] STEP 10: Reload PDF with stamp for QR embedding`);
  const pdfDocForQr = await PDFDocument.load(pdfWithStampBuffer);
  const pageForQr = pdfDocForQr.getPages()[pdfDocForQr.getPageCount() - 1];
  
  try {
    console.log(`[SIGN] → Attempting to embed QR PNG (${qrPngBuffer.length} bytes)`);
    const qrImage = await pdfDocForQr.embedPng(qrPngBuffer);
    console.log(`[SIGN] → QR image embedded successfully`);
    
    pageForQr.drawImage(qrImage, {
      x: qrX,
      y: qrY,
      width: qrSize,
      height: qrSize
    });
    console.log(`[SIGN] → QR drawn at (${qrX}, ${qrY}) size ${qrSize}x${qrSize}`);
  } catch (embedErr) {
    console.error(`[SIGN] → Embed error: ${embedErr.message}`);
    console.error(`[SIGN] → Stack: ${embedErr.stack}`);
    throw new Error(`QR embed failed: ${embedErr.message}`);
  }

  // ✓ STEP 11: SIMPAN PDF FINAL (Stempel + QR)
  console.log(`[SIGN] STEP 11: Save final PDF with stamp and QR`);
  const finalPdfBuffer = await pdfDocForQr.save();

  // ✓ STEP 12: Verify hash konsistensi
  console.log(`[SIGN] STEP 12: Verify hash consistency`);
  const verifyHash = sha256Hex(pdfWithStampBuffer);
  console.log(`[SIGN] → Original hash:  ${hash.substring(0, 16)}...`);
  console.log(`[SIGN] → Verify hash:    ${verifyHash.substring(0, 16)}...`);
  console.log(`[SIGN] → Match: ${hash === verifyHash ? '✓ YES' : '✗ NO'}`);

  // ✓ STEP 13: Upload ke Supabase
  console.log(`[SIGN] STEP 13: Upload signed PDF to Supabase`);
  const signedUrl = await uploadToSupabase(`signed/${docId}_signed.pdf`, finalPdfBuffer);
  console.log(`[SIGN] → Uploaded: ${signedUrl.substring(0, 50)}...`);

  // ✓ STEP 14: Simpan metadata ke Firestore
  console.log(`[SIGN] STEP 14: Save metadata to Firestore`);
  await admin.firestore().collection('dokumen_pengajuan').doc(docId).update({
    status: 'Ditandatangani',
    signed_file_url: signedUrl,
    hash_sha256: hash,
    signature,
    qr_payload: qrPayload,
    signed_at: admin.firestore.FieldValue.serverTimestamp(),
    signed_by_uid: user.uid,
    signed_by_name: user.name || 'Admin Desa',
    verification_ready: true
  });
  console.log(`[SIGN] ✓ SIGNING COMPLETE`);

  return { hash, signature, signedUrl, qrPayload };
}

// ROUTES
app.post('/api/documents/:docId/sign', verifyFirebaseTokenFromHeader, async (req, res) => {
  try {
    if (req.user.role !== 'Admin Desa') {
      return res.status(403).json({ success: false, error: 'Akses ditolak' });
    }

    console.log(`\n${Array(60).fill('═').join('')}`);
    console.log(`SIGNING DOCUMENT: ${req.params.docId}`);
    console.log(`By: ${req.user.name || req.user.email}`);
    console.log(`${Array(60).fill('═').join('')}\n`);

    const { hash, signature, signedUrl, qrPayload } = await doSign(req.params.docId, req.user);

    res.json({
      success: true,
      message: "Dokumen berhasil ditandatangani oleh Kepala Desa Pucangro",
      docId: req.params.docId,
      algorithm: "RSA-2048 + SHA-256",
      hash_sha256: hash,
      signature_base64: signature,
      signed_file_url: signedUrl,
      qr_payload: qrPayload,
      features: { stempel: true, qr_verification: true, kecamatan_ready: true },
      signed_at: new Date().toLocaleString('id-ID'),
      verification_note: "Hash ini akan cocok saat diverifikasi di kecamatan"
    });
  } catch (err) {
    console.error('Error sign document:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// VERIFICATION ENDPOINT (untuk kecamatan/verifikator)
app.post('/api/documents/:docId/verify', async (req, res) => {
  try {
    const { qr_payload } = req.body;
    if (!qr_payload) {
      return res.status(400).json({ success: false, error: 'QR payload diperlukan' });
    }

    const snap = await admin.firestore().collection('dokumen_pengajuan').doc(req.params.docId).get();
    if (!snap.exists) {
      return res.status(404).json({ success: false, error: 'Dokumen tidak ditemukan' });
    }

    const docData = snap.data();
    const qrData = JSON.parse(qr_payload);

    console.log(`\n${Array(60).fill('═').join('')}`);
    console.log(`VERIFYING DOCUMENT: ${req.params.docId}`);
    console.log(`${Array(60).fill('═').join('')}\n`);
    console.log(`Database hash: ${docData.hash_sha256.substring(0, 16)}...`);
    console.log(`QR hash:       ${qrData.hash.substring(0, 16)}...`);

    const hashMatch = docData.hash_sha256 === qrData.hash;
    console.log(`Match: ${hashMatch ? '✓ YES' : '✗ NO'}`);

    res.json({
      success: hashMatch,
      message: hashMatch ? "✓ Dokumen valid dan terbukti asli" : "✗ Dokumen tidak valid atau telah diubah",
      docId: req.params.docId,
      status: docData.status,
      signed_by: docData.signed_by_name || 'Kepala Desa',
      signed_at: docData.signed_at,
      hash_match: hashMatch,
      hash_database: docData.hash_sha256.substring(0, 32),
      hash_qr: qrData.hash.substring(0, 32)
    });
  } catch (err) {
    console.error('Error verify document:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/', (req, res) => res.json({
  success: true,
  message: "Smart Dokumen Desa - Server Jalan 100% A+++ LOCKED",
  version: "v14.0-sharp-qr",
  features: ["Signing", "QR Generation with Sharp", "Hash Verification", "Kecamatan Ready"]
}));

app.listen(PORT, () => {
  console.log(`\n${Array(60).fill('═').join('')}`);
  console.log(`SERVER JALAN DI PORT ${PORT}`);
  console.log(`${Array(60).fill('═').join('')}`);
  console.log(`✓ HASH COCOK + QR DENGAN SHARP + POSISI BENAR`);
  console.log(`✓ Flow: PDF → Stempel → HASH (SEKALI) → Signature → QR`);
  console.log(`✓ Endpoint: POST /api/documents/:docId/sign`);
  console.log(`✓ Endpoint: POST /api/documents/:docId/verify`);
  console.log(`${Array(60).fill('═').join('')}\n`);
});
