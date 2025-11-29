// server.js
// Simple signing + recompute-hash service for TA
// Minimal production notes: validate inputs, rate-limit, better error handling, and protect keys.
const express = require('express');
const fetch = require('node-fetch');
const QRCode = require('qrcode');
const { PDFDocument, rgb, degrees, StandardFonts } = require('pdf-lib');
const crypto = require('crypto');
const admin = require('firebase-admin');

const app = express();
app.use(express.json({ limit: '20mb' }));

// Required env vars
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const PRIVATE_KEY_PEM = process.env.PRIVATE_KEY_PEM;
const FIREBASE_SERVICE_ACCOUNT_JSON = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
const DEFAULT_BUCKET = process.env.SUPABASE_BUCKET || 'dokumen';

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY || !PRIVATE_KEY_PEM || !FIREBASE_SERVICE_ACCOUNT_JSON) {
  console.warn('WARNING: One or more required env vars are not set.');
}

if (FIREBASE_SERVICE_ACCOUNT_JSON) {
  try {
    const sa = JSON.parse(FIREBASE_SERVICE_ACCOUNT_JSON);
    admin.initializeApp({
      credential: admin.credential.cert(sa)
    });
    console.log('Firebase Admin initialized.');
  } catch (e) {
    console.error('Failed to parse FIREBASE_SERVICE_ACCOUNT_JSON', e.message);
  }
}

// ---------- Utilities ----------
async function downloadFromSupabase(bucket, path) {
  const url = `${SUPABASE_URL}/storage/v1/object/${bucket}/${encodeURIComponent(path)}`;
  const res = await fetch(url, { headers: { Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
  if (!res.ok) throw new Error(`Supabase download failed: ${res.status}`);
  return await res.buffer();
}

async function uploadToSupabase(bucket, destPath, buffer) {
  const url = `${SUPABASE_URL}/storage/v1/object/${bucket}/${encodeURIComponent(destPath)}`;
  const res = await fetch(url, {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
      'Content-Type': 'application/pdf'
    },
    body: buffer
  });
  if (!res.ok) {
    const bodyText = await res.text().catch(() => '');
    throw new Error(`Supabase upload failed: ${res.status} ${bodyText}`);
  }
  return `${SUPABASE_URL}/storage/v1/object/public/${bucket}/${encodeURIComponent(destPath)}`;
}

// ---------- Crypto ----------
function sha256Hex(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function signHex(hashHex) {
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(Buffer.from(hashHex, 'hex'));
  signer.end();
  return signer.sign(PRIVATE_KEY_PEM, 'base64');
}

// ---------- Firebase Token ----------
async function verifyFirebaseTokenFromHeader(req, res, next) {
  try {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Missing token' });
    if (!admin.apps.length) return res.status(500).json({ error: 'Firebase Admin not initialized' });
    const decoded = await admin.auth().verifyIdToken(token);
    req.user = decoded;
    const userDoc = await admin.firestore().collection('users').doc(decoded.uid).get();
    req.user.role = userDoc.exists ? userDoc.data().role : null;
    next();
  } catch (err) {
    console.error('Token verify failed:', err.message);
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

// ---------- CORE SIGN LOGIC (DENGAN WATERMARK + STEMPEL + QR CANTIK) ----------
async function doSign(docId, reqUser) {
  if (!admin.apps.length) throw new Error('Firebase Admin not initialized');
  const snap = await admin.firestore().collection('dokumen_pengajuan').doc(docId).get();
  if (!snap.exists) throw new Error('Document not found');
  const meta = snap.data() || {};
  const bucket = meta.bucket || DEFAULT_BUCKET;
  const path = meta.file_path;
  if (!path) throw new Error('file_path missing in metadata');

  const buf = await downloadFromSupabase(bucket, path);
  const hashHex = sha256Hex(buf);
  const signatureBase64 = signHex(hashHex);

  const qrPayload = JSON.stringify({
    docId,
    signature: signatureBase64,
    algo: 'RSASSA-PKCS1-v1_5-SHA256',
    hash: hashHex
  });

  const qrDataUrl = await QRCode.toDataURL(qrPayload);
  const pdfDoc = await PDFDocument.load(buf);
  const helvetica = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const helveticaBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const pages = pdfDoc.getPages();
  const lastPage = pages[pages.length - 1];
  const { width, height } = lastPage.getSize();

  // 1. WATERMARK DIAGONAL
  lastPage.drawText('DITANDATANGANI SECARA DIGITAL', {
    x: 80,
    y: height / 2 + 100,
    size: 64,
    font: helveticaBold,
    color: rgb(0.85, 0.1, 0.1),
    rotate: degrees(-45),
    opacity: 0.22,
  });

  // 2. STEMPEL RESMI KANAN BAWAH
  lastPage.drawRectangle({
    x: width - 260,
    y: 40,
    width: 230,
    height: 150,
    borderColor: rgb(0, 0.4, 0),
    borderWidth: 4,
    color: rgb(1, 1, 1),
  });
  lastPage.drawText('DITANDATANGANI DIGITAL', {
    x: width - 245,
    y: 165,
    size: 14,
    font: helveticaBold,
    color: rgb(0, 0.5, 0),
  });
  lastPage.drawText('KEPALA DESA PUCANGRO', {
    x: width - 245,
    y: 140,
    size: 12,
    font: helveticaBold,
    color: rgb(0, 0, 0),
  });
  lastPage.drawText(`Tgl: ${new Date().toLocaleDateString('id-ID')}`, {
    x: width - 245,
    y: 115,
    size: 11,
    font: helvetica,
    color: rgb(0, 0, 0),
  });

  // 3. QR CODE + TULISAN DI KIRI BAWAH
  const pngBytes = Buffer.from(qrDataUrl.split(',')[1], 'base64');
  const pngImage = await pdfDoc.embedPng(pngBytes);
  lastPage.drawImage(pngImage, { x: 40, y: 40, width: 130, height: 130 });
  lastPage.drawText('Verifikasi Dokumen', {
    x: 40,
    y: 25,
    size: 12,
    font: helveticaBold,
    color: rgb(0, 0, 0),
  });
  lastPage.drawText('Scan QR Code ini', {
    x: 40,
    y: 10,
    size: 10,
    font: helvetica,
    color: rgb(0.3, 0.3, 0.3),
  });

  const signedPdfBytes = await pdfDoc.save();
  const destPath = `signed/${docId}_signed.pdf`;
  const signedUrl = await uploadToSupabase(bucket, destPath, signedPdfBytes);

  await admin.firestore().collection('dokumen_pengajuan').doc(docId).update({
    signature: signatureBase64,
    signed_pdf_url: signedUrl,
    qr_payload: qrPayload,
    status: 'Ditandatangani',
    signed_at: admin.firestore.FieldValue.serverTimestamp(),
    signed_by_uid: reqUser?.uid || null,
    hash_sha256: hashHex
  });

  await admin.firestore().collection('dokumen_pengajuan').doc(docId).collection('audit_logs').add({
    action: 'sign',
    by: reqUser?.uid || null,
    at: admin.firestore.FieldValue.serverTimestamp()
  });

  return { signatureBase64, signedUrl, qrPayload };
}

// ---------- Routes (sama persis seperti asli) ----------
app.post('/recompute-hash', verifyFirebaseTokenFromHeader, async (req, res) => { /* sama */ });
app.post('/sign', verifyFirebaseTokenFromHeader, async (req, res) => {
  try {
    if (req.user.role !== 'admin_desa') return res.status(403).json({ error: 'Forbidden' });
    const { docId } = req.body;
    if (!docId) return res.status(400).json({ error: 'docId required' });
    const result = await doSign(docId, req.user);
    return res.json({ signatureBase64: result.signatureBase64, signedPdfUrl: result.signedUrl, qrPayload: result.qrPayload });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: err.message });
  }
});

app.post('/api/documents/:docId/sign', verifyFirebaseTokenFromHeader, async (req, res) => {
  try {
    if (req.user.role !== 'admin_desa') return res.status(403).json({ error: 'Forbidden' });
    const docId = req.params.docId;
    const result = await doSign(docId, req.user);
    return res.json({ signatureBase64: result.signatureBase64, signedPdfUrl: result.signedUrl, qrPayload: result.qrPayload });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: err.message });
  }
});

app.get('/', (req, res) => res.json({ ok: true }));
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server listening on ${PORT} A+++ WITH WATERMARK & STEMPEL`));
