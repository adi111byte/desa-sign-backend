// server.js
// Simple signing + recompute-hash service for TA
// NOTE: production-ready improvements (rate limit, better error handling, input validation) recommended.

const express = require('express');
const fetch = require('node-fetch');
const QRCode = require('qrcode');
const { PDFDocument } = require('pdf-lib');
const crypto = require('crypto');
const admin = require('firebase-admin');

const app = express();
app.use(express.json({ limit: '20mb' }));

// Required env vars (set in Railway)
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const PRIVATE_KEY_PEM = process.env.PRIVATE_KEY_PEM;
const FIREBASE_SERVICE_ACCOUNT_JSON = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
const DEFAULT_BUCKET = process.env.SUPABASE_BUCKET || 'dokumen';

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY || !PRIVATE_KEY_PEM || !FIREBASE_SERVICE_ACCOUNT_JSON) {
  console.error('Missing required environment variables. Check SUPABASE_URL, SUPABASE_SERVICE_KEY, PRIVATE_KEY_PEM, FIREBASE_SERVICE_ACCOUNT_JSON');
  // don't exit; in Railway you can set env before starting
}

// Initialize Firebase Admin if credential provided
if (FIREBASE_SERVICE_ACCOUNT_JSON) {
  try {
    const sa = JSON.parse(FIREBASE_SERVICE_ACCOUNT_JSON);
    admin.initializeApp({
      credential: admin.credential.cert(sa),
      // optionally add databaseURL if used
    });
    console.log('Firebase Admin initialized.');
  } catch (e) {
    console.error('Failed to parse FIREBASE_SERVICE_ACCOUNT_JSON', e.message);
  }
}

// utility: download object from Supabase storage (service key required)
async function downloadFromSupabase(bucket, path) {
  const url = `${SUPABASE_URL}/storage/v1/object/${bucket}/${encodeURIComponent(path)}`;
  const res = await fetch(url, { headers: { Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
  if (!res.ok) throw new Error(`Supabase download failed: ${res.status}`);
  return await res.buffer();
}

// utility: upload object to Supabase
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
  // public URL pattern (if bucket configured public), otherwise use presigned strategy
  const publicUrl = `${SUPABASE_URL}/storage/v1/object/public/${bucket}/${encodeURIComponent(destPath)}`;
  return publicUrl;
}

function sha256Hex(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function signHex(hashHex) {
  const signer = crypto.createSign('RSA-SHA256');
  // We sign the binary of the hash so client/server agree on what was signed
  signer.update(Buffer.from(hashHex, 'hex'));
  signer.end();
  return signer.sign(PRIVATE_KEY_PEM, 'base64');
}

// middleware: verify firebase id token
async function verifyFirebaseTokenFromHeader(req, res, next) {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Missing token' });
    if (!admin.apps.length) return res.status(500).json({ error: 'Firebase Admin not initialized' });
    const decoded = await admin.auth().verifyIdToken(token);
    req.user = decoded;
    // optionally fetch role from firestore
    const userDoc = await admin.firestore().collection('users').doc(decoded.uid).get();
    req.user.role = userDoc.exists ? userDoc.data().role : null;
    next();
  } catch (err) {
    console.error('Token verify failed:', err.message);
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

// POST /recompute-hash
// body: { "docId": "..." }
app.post('/recompute-hash', verifyFirebaseTokenFromHeader, async (req, res) => {
  try {
    if (req.user.role !== 'admin_desa') return res.status(403).json({ error: 'Forbidden' });
    const { docId } = req.body;
    if (!docId) return res.status(400).json({ error: 'docId required' });

    const snap = await admin.firestore().collection('dokumen_pengajuan').doc(docId).get();
    if (!snap.exists) return res.status(404).json({ error: 'Document not found' });
    const meta = snap.data();
    const bucket = meta.bucket || DEFAULT_BUCKET;
    const path = meta.file_path;
    if (!path) return res.status(400).json({ error: 'file_path missing in metadata' });

    const buf = await downloadFromSupabase(bucket, path);
    const newHash = sha256Hex(buf);
    const storedHash = meta.hash_sha256 || null;
    const match = storedHash ? (newHash === storedHash) : false;

    await admin.firestore().collection('dokumen_pengajuan').doc(docId).update({
      last_integrity_check: admin.firestore.FieldValue.serverTimestamp(),
      integrity_ok: match
    });

    return res.json({ match, newHash, storedHash });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: err.message });
  }
});

// POST /sign
// body: { "docId": "..." }
// requires admin role
app.post('/sign', verifyFirebaseTokenFromHeader, async (req, res) => {
  try {
    if (req.user.role !== 'admin_desa') return res.status(403).json({ error: 'Forbidden' });
    const { docId } = req.body;
    if (!docId) return res.status(400).json({ error: 'docId required' });

    const snap = await admin.firestore().collection('dokumen_pengajuan').doc(docId).get();
    if (!snap.exists) return res.status(404).json({ error: 'Document not found' });
    const meta = snap.data();
    const bucket = meta.bucket || DEFAULT_BUCKET;
    const path = meta.file_path;
    if (!path) return res.status(400).json({ error: 'file_path missing in metadata' });

    // download original pdf
    const buf = await downloadFromSupabase(bucket, path);

    // compute hash and sign
    const hashHex = sha256Hex(buf);
    const signatureBase64 = signHex(hashHex);

    // generate QR payload (you may customize)
    const qrPayload = JSON.stringify({ docId, signature: signatureBase64, algo: 'RSASSA-PKCS1-v1_5-SHA256' });
    const qrDataUrl = await QRCode.toDataURL(qrPayload);

    // embed QR into PDF (bottom-right of last page)
    const pdfDoc = await PDFDocument.load(buf);
    const pages = pdfDoc.getPages();
    const lastPage = pages[pages.length - 1];
    // embed image
    const pngBytes = Buffer.from(qrDataUrl.split(',')[1], 'base64');
    const pngImage = await pdfDoc.embedPng(pngBytes);
    const { width, height } = lastPage.getSize();
    // image size in points
    const imgW = Math.min(140, width * 0.2);
    const imgH = Math.min(140, height * 0.2);
    lastPage.drawImage(pngImage, { x: width - imgW - 32, y: 32, width: imgW, height: imgH });

    const signedPdfBytes = await pdfDoc.save();

    // upload signed PDF
    const destPath = `signed/${docId}_signed.pdf`;
    const signedUrl = await uploadToSupabase(bucket, destPath, signedPdfBytes);

    // update firestore
    await admin.firestore().collection('dokumen_pengajuan').doc(docId).update({
      signature: signatureBase64,
      signed_pdf_url: signedUrl,
      status: 'Diterima',
      signed_at: admin.firestore.FieldValue.serverTimestamp(),
      signed_by_uid: req.user.uid
    });

    // optional: add audit log
    await admin.firestore().collection('dokumen_pengajuan').doc(docId).collection('audit_logs').add({
      action: 'sign',
      by: req.user.uid,
      at: admin.firestore.FieldValue.serverTimestamp()
    });

    return res.json({ signatureBase64, signedPdfUrl: signedUrl });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: err.message });
  }
});

// health
app.get('/', (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server listening on ${PORT}`));
