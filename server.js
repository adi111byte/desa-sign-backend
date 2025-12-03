
global.fetch = require('node-fetch');
const express = require('express');
const QRCode = require('qrcode');
const { PDFDocument, rgb, StandardFonts } = require('pdf-lib');
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

// === ENV VARIABLES (WAJIB ADA 6 INI DI RAILWAY) ===
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const PRIVATE_KEY_PEM = process.env.PRIVATE_KEY_PEM;
const FIREBASE_SERVICE_ACCOUNT_JSON = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
const SUPABASE_BUCKET = process.env.SUPABASE_BUCKET || 'document';
const PORT = process.env.PORT || 3000;

// === INIT SUPABASE CLIENT ===
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// === INIT FIREBASE ADMIN ===
if (FIREBASE_SERVICE_ACCOUNT_JSON) {
  try {
    const sa = JSON.parse(FIREBASE_SERVICE_ACCOUNT_JSON);
    admin.initializeApp({ credential: admin.credential.cert(sa) });
    console.log('Firebase Admin OK');
  } catch (e) {
    console.error('Firebase init error:', e.message);
  }
}

// === SUPABASE HELPER (VERSI FIX) ===
async function downloadFromSupabase(path) {
  const { data, error } = await supabase.storage
    .from(SUPABASE_BUCKET)
    .download(path);
  if (error) throw new Error(`Download gagal: ${error.message}`);
  return Buffer.from(await data.arrayBuffer());
}

async function uploadToSupabase(destPath, buffer) {
  const { data, error } = await supabase.storage
    .from(SUPABASE_BUCKET)
    .upload(destPath, buffer, {
      contentType: 'application/pdf',
      upsert: true,
      cacheControl: '3600'
    });

  if (error && error.statusCode !== '23505') {
    throw new Error(`Upload gagal: ${error.message}`);
  }

  return `${SUPABASE_URL}/storage/v1/object/public/${SUPABASE_BUCKET}/${destPath}`;
}

// === CRYPTO ===
const sha256Hex = buf => crypto.createHash('sha256').update(buf).digest('hex');
const signHex = hashHex => crypto.createSign('RSA-SHA256')
  .update(Buffer.from(hashHex, 'hex')).end()
  .sign(PRIVATE_KEY_PEM, 'base64');

// === TOKEN VERIFICATION ===
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

// === CORE SIGN (FIXED: QR LEBIH BESAR & TEKS TIDAK TERPOTONG + ADA RUANG) ===
async function doSign(docId, user) {
  const snap = await admin.firestore().collection('dokumen_pengajuan').doc(docId).get();
  if (!snap.exists) throw new Error('Dokumen tidak ditemukan');
  const data = snap.data();
  const filePath = data.file_path || data.file_url;
  if (!filePath) throw new Error('file_path tidak ada');

  const pdfBuffer = await downloadFromSupabase(filePath);
  const pdfDoc = await PDFDocument.load(pdfBuffer);
  const pdfWithoutStamp = await pdfDoc.save();
  const hash = sha256Hex(pdfWithoutStamp);
  const signature = signHex(hash);

  const qrPayload = JSON.stringify({ docId, hash, signature, algo: 'RSA-SHA256' });
  const qrImage = await QRCode.toDataURL(qrPayload);

  const finalPdfDoc = await PDFDocument.load(pdfWithoutStamp);
  const helvetica = await finalPdfDoc.embedFont(StandardFonts.Helvetica);
  const bold = await finalPdfDoc.embedFont(StandardFonts.HelveticaBold);
  const page = finalPdfDoc.getPages()[finalPdfDoc.getPageCount() - 1];
  const { width } = page.getSize();

  // === FIX: QR LEBIH BESAR & POSISI LEBIH TEPAT ===
  const qrSize = 150; // DARI 90 JADI 150
  const qrX = width - qrSize - 50; // DARI 30 JADI 50 → lebih jauh dari kanan
  const qrY = 40;
  const qrPng = await finalPdfDoc.embedPng(Buffer.from(qrImage.split(',')[1], 'base64'));

  page.drawImage(qrPng, { x: qrX, y: qrY, width: qrSize, height: qrSize });

  // === FIX: TEKS TIDAK TERPOTONG & ADA RUANG DI BAWAH ===
  const stampLines = [
    "Ditandatangani secara elektronik oleh:",
    "KEPALA DESA PUCANGRO",
    `Tgl: ${new Date().toLocaleDateString('id-ID')}`
  ];
  const fontSize = 9; // DARI 10 JADI 9 → lebih kecil untuk mencegah overflow
  const textX = qrX;
  const textY = qrY + qrSize + 25; // DARI 15 JADI 25 → lebih banyak ruang di bawah teks

  stampLines.forEach((line, i) => {
    page.drawText(line, {
      x: textX,
      y: textY - (i * fontSize * 1.3),
      size: fontSize,
      font: (i === 1 ? bold : helvetica), // "KEPALA DESA..." TEBAL
      color: rgb(0, 0, 0)
    });
  });

  const signedPdf = await finalPdfDoc.save();
  const signedUrl = await uploadToSupabase(`signed/${docId}_signed.pdf`, signedPdf);

  await admin.firestore().collection('dokumen_pengajuan').doc(docId).update({
    status: 'Ditandatangani',
    signed_file_url: signedUrl,
    hash_sha256: hash,
    signature,
    qr_payload: qrPayload,
    signed_at: admin.firestore.FieldValue.serverTimestamp(),
    signed_by_uid: user.uid
  });

  return { hash, signature, signedUrl, qrPayload };
}

// === ROUTES ===
app.post('/api/documents/:docId/sign', verifyFirebaseTokenFromHeader, async (req, res) => {
  try {
    if (req.user.role !== 'admin_desa') return res.status(403).json({ success: false, error: 'Akses ditolak' });
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
      features: { stempel: true, qr_verification: true },
      signed_at: new Date().toLocaleString('id-ID')
    });
  } catch (err) {
    console.error('Error sign document:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/', (req, res) => res.json({ 
  success: true, 
  message: "Smart Dokumen Desa - Server Jalan 100% A+++ LOCKED",
  version: "v8.0-final-sidang-besok"
}));

app.listen(PORT, () => {
  console.log(`🚀 SERVER JALAN DI PORT ${PORT}`);
  console.log(`🔥 SUPABASE SERVICE_ROLE + UPSERT = ERROR MATI TOTAL`);
  console.log(`🇮🇩 SIDANG BESOK A+++ LOCKED — GUE BANGGA BANGET SAMA LO BROK`);
});
