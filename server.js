// server.js - Smart Dokumen Desa (FINAL VERSION )
const express = require('express');
const fetch = require('node-fetch');
const QRCode = require('qrcode');
const { PDFDocument, rgb, degrees, StandardFonts } = require('pdf-lib');
const crypto = require('crypto');
const admin = require('firebase-admin');
const helmet = require('helmet');
const rateLimit = require("express-rate-limit");

const app = express();
app.use(express.json({ limit: '20mb' }));
app.use(helmet());

// Rate limit anti spam
const limiter = rateLimit({
  windowMs: 60_000,
  max: 6,
  message: { success: false, error: "Terlalu banyak percobaan. Tunggu 1 menit." }
});
app.use("/api/documents", limiter);

// === EXACTLY YOUR 6 VARIABLES ONLY ===
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const PRIVATE_KEY_PEM = process.env.PRIVATE_KEY_PEM;
const FIREBASE_SERVICE_ACCOUNT_JSON = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
const SUPABASE_BUCKET = process.env.SUPABASE_BUCKET || 'document';
const PORT = process.env.PORT || 3000;

// Firebase Admin Init
if (FIREBASE_SERVICE_ACCOUNT_JSON) {
  try {
    const sa = JSON.parse(FIREBASE_SERVICE_ACCOUNT_JSON);
    admin.initializeApp({ credential: admin.credential.cert(sa) });
    console.log('Firebase Admin OK');
  } catch (e) {
    console.error('Firebase init error:', e.message);
  }
}

// === SUPABASE HELPER ===
async function downloadFromSupabase(path) {
  const url = `${SUPABASE_URL}/storage/v1/object/${SUPABASE_BUCKET}/${encodeURIComponent(path)}`;
  const res = await fetch(url, { headers: { Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
  if (!res.ok) throw new Error(`Download failed: ${res.status}`);
  return await res.buffer();
}

async function uploadToSupabase(destPath, buffer) {
  const url = `${SUPABASE_URL}/storage/v1/object/${SUPABASE_BUCKET}/${encodeURIComponent(destPath)}`;
  const res = await fetch(url, {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
      'Content-Type': 'application/pdf'
    },
    body: buffer
  });
  if (!res.ok) throw new Error(`Upload failed: ${res.status}`);
  return `${SUPABASE_URL}/storage/v1/object/public/${SUPABASE_BUCKET}/${encodeURIComponent(destPath)}`;
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

// === CORE SIGN (WATERMARK + STEMPEL + QR) ===
async function doSign(docId, user) {
  const snap = await admin.firestore().collection('dokumen_pengajuan').doc(docId).get();
  if (!snap.exists) throw new Error('Dokumen tidak ditemukan');
  const data = snap.data();
  const filePath = data.file_path || data.file_url;
  if (!filePath) throw new Error('file_path tidak ada');

  const pdfBuffer = await downloadFromSupabase(filePath);
  const hash = sha256Hex(pdfBuffer);
  const signature = signHex(hash);

  const qrPayload = JSON.stringify({ docId, hash, signature, algo: 'RSA-SHA256' });
  const qrImage = await QRCode.toDataURL(qrPayload);

  const pdfDoc = await PDFDocument.load(pdfBuffer);
  const helvetica = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const bold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const page = pdfDoc.getPages()[pdfDoc.getPageCount() - 1];
  const { width, height } = page.getSize();

  // Watermark diagonal
  page.drawText('DITANDATANGANI SECARA DIGITAL', {
    x: 80, y: height / 2 + 100, size: 64, font: bold,
    color: rgb(0.85, 0.1, 0.1), rotate: degrees(-45), opacity: 0.22
  });

  // Stempel + QR
  page.drawRectangle({ x: width - 260, y: 40, width: 230, height: 150, borderColor: rgb(0,0.4,0), borderWidth: 4 });
  page.drawText('KEPALA DESA PUCANGRO', { x: width - 245, y: 140, size: 12, font: bold });
  page.drawText(`Tgl: ${new Date().toLocaleDateString('id-ID')}`, { x: width - 245, y: 115, size: 11, font: helvetica });

  const qrPng = await pdfDoc.embedPng(Buffer.from(qrImage.split(',')[1], 'base64'));
  page.drawImage(qrPng, { x: 40, y: 40, width: 130, height: 130 });
  page.drawText('Scan QR untuk verifikasi', { x: 40, y: 20, size: 10, font: helvetica });

  const signedPdf = await pdfDoc.save();
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

// === ROUTE UTAMA ===
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
      features: { watermark: true, stempel: true, qr_verification: true },
      signed_at: new Date().toLocaleString('id-ID')
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/', (req, res) => res.json({ success: true, message: "Smart Dokumen Desa - Ready A+++" }));

app.listen(PORT, () => console.log(`Server jalan di port ${PORT} — RSA + Watermark + QR = LOCKED`));
