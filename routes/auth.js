const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../db');
const { sendVerificationEmail, sendPasswordResetEmail, sendLockoutWarningEmail } = require('../services/mailService');
const { OAuth2Client } = require('google-auth-library');
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');

// Limitador
const recoveryLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, 
  max: 3, 
  message: { message: 'Límite excedido. Intenta en una hora.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Validaciones
const registerValidationRules = [
  body('nombre').trim().escape(),
  body('apellidos').trim().escape(),
  body('email').isEmail().normalizeEmail(),
  body('telefono').trim().escape(),
  body('password').isLength({ min: 8 }),
  body('preguntaSecreta').trim().notEmpty(),
  body('respuestaSecreta').trim().notEmpty().escape()
];

// --- 1. REGISTRO (Igual) ---
router.post('/register', registerValidationRules, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ message: errors.array()[0].msg });

  try {
    const { nombre, apellidos, telefono, email, password, preguntaSecreta, respuestaSecreta } = req.body;
    const [existingUser] = await db.query('SELECT id FROM usuarios WHERE email = ?', [email]);
    if (existingUser.length > 0) return res.status(409).json({ message: 'El correo ya está registrado.' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const hashedAnswer = await bcrypt.hash(respuestaSecreta.toLowerCase().trim(), salt);
    const emailToken = Math.floor(100000 + Math.random() * 900000).toString();

    const sql = `INSERT INTO usuarios (nombre, apellidos, telefono, email, password, pregunta_secreta, respuesta_secreta, token_email) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
    await db.query(sql, [nombre, apellidos, telefono, email, hashedPassword, preguntaSecreta, hashedAnswer, emailToken]);
    await sendVerificationEmail(email, emailToken);

    res.status(201).json({ message: 'Registro exitoso. Revisa tu email.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error en el servidor.' });
  }
});

// --- 2. LOGIN (Con Cookie) ---
router.post('/login', async (req, res) => {
  try {
    const { email, password, rol } = req.body;
    if (!email || !password || !rol) return res.status(400).json({ message: 'Faltan datos.' });

    const [users] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);
    if (users.length === 0) return res.status(401).json({ message: 'Credenciales inválidas.' });
    const user = users[0];

    const [lock] = await db.query('SELECT (lockout_expires > UTC_TIMESTAMP()) AS is_locked FROM usuarios WHERE id = ?', [user.id]);
    if (lock[0].is_locked) return res.status(429).json({ message: 'Cuenta bloqueada 5 min.' });

    if (!user.password) return res.status(400).json({ message: 'Usa Google Login.' });

    const isMatch = await bcrypt.compare(password, user.password);

    if (isMatch) {
      if (user.tipo_usuario !== rol) return res.status(401).json({ message: 'Rol incorrecto.' });
      if (user.estado_cuenta === 'pendiente') return res.status(403).json({ message: 'Cuenta no activada.' });

      await db.query('UPDATE usuarios SET login_attempts = 0, lockout_expires = NULL WHERE id = ?', [user.id]);

      const token = jwt.sign({ userId: user.id, email: user.email, tipo_usuario: user.tipo_usuario }, process.env.JWT_SECRET, { expiresIn: '1d' });

      // --- ENVIAR COOKIE ---
      res.cookie('token', token, {
        httpOnly: true,
        secure: true, // HTTPS
        sameSite: 'none', // Necesario para cross-site en localhost (o 'lax' si es mismo dominio)
        maxAge: 24 * 60 * 60 * 1000 // 1 día
      });

      return res.status(200).json({
        message: 'Login exitoso.',
        // YA NO enviamos token en JSON
        user: { id: user.id, nombre: user.nombre, email: user.email, tipo_usuario: user.tipo_usuario }
      });

    } else {
      const newAttempts = user.login_attempts + 1;
      if (newAttempts >= 3) {
        await db.query('UPDATE usuarios SET login_attempts = ?, lockout_expires = (UTC_TIMESTAMP() + INTERVAL 5 MINUTE) WHERE id = ?', [newAttempts, user.id]);
        await sendLockoutWarningEmail(user.email);
        return res.status(429).json({ message: 'Bloqueado por intentos fallidos.' });
      } else {
        await db.query('UPDATE usuarios SET login_attempts = ? WHERE id = ?', [newAttempts, user.id]);
        return res.status(401).json({ message: `Credenciales inválidas. Quedan ${3 - newAttempts} intentos.` });
      }
    }
  } catch (error) {
    res.status(500).json({ message: 'Error servidor.' });
  }
});

// --- 3. GOOGLE LOGIN (Con Cookie) ---
router.post('/google-login', async (req, res) => {
  const { credential } = req.body;
  try {
    const ticket = await client.verifyIdToken({ idToken: credential, audience: process.env.GOOGLE_CLIENT_ID });
    const { email, given_name, family_name } = ticket.getPayload();
    let [users] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);
    let user;

    if (users.length === 0) {
      const [resDB] = await db.query(`INSERT INTO usuarios (nombre, apellidos, email, tipo_usuario, estado_cuenta) VALUES (?, ?, ?, 'cliente', 'activo')`, [given_name, family_name || '', email]);
      [users] = await db.query('SELECT * FROM usuarios WHERE id = ?', [resDB.insertId]);
    }
    user = users[0];

    const [lock] = await db.query('SELECT (lockout_expires > UTC_TIMESTAMP()) AS is_locked FROM usuarios WHERE id = ?', [user.id]);
    if (lock[0].is_locked) return res.status(429).json({ message: 'Cuenta bloqueada.' });
    await db.query('UPDATE usuarios SET login_attempts = 0, lockout_expires = NULL WHERE id = ?', [user.id]);

    const token = jwt.sign({ userId: user.id, email: user.email, tipo_usuario: user.tipo_usuario }, process.env.JWT_SECRET, { expiresIn: '1d' });

    // --- ENVIAR COOKIE ---
    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 24 * 60 * 60 * 1000
    });

    res.status(200).json({
      message: 'Login Google exitoso.',
      user: { id: user.id, nombre: user.nombre, email: user.email, tipo_usuario: user.tipo_usuario }
    });

  } catch (error) {
    res.status(401).json({ message: 'Error Google Auth' });
  }
});

// --- 4. LOGOUT (Borrar Cookie) ---
router.post('/logout', async (req, res) => {
  try {
    // Opcional: Agregar token a lista negra si lo lees de la cookie antes de borrar
    const token = req.cookies.token;
    if (token) {
        const decoded = jwt.decode(token);
        const expiration = decoded && decoded.exp ? new Date(decoded.exp * 1000) : new Date(Date.now() + 24*60*60*1000);
        await db.query('INSERT INTO token_blacklist (token, fecha_expiracion) VALUES (?, ?)', [token, expiration]);
    }

    res.clearCookie('token', {
        httpOnly: true,
        secure: true,
        sameSite: 'none'
    });
    res.status(200).json({ message: 'Sesión cerrada.' });
  } catch (error) {
    res.status(200).json({ message: 'Sesión cerrada.' });
  }
});

// --- Rutas de Recuperación y Verificación (Sin cambios importantes) ---
router.post('/verify-code', async (req, res) => {
    try {
        const { email, code } = req.body;
        const [users] = await db.query('SELECT id, token_email FROM usuarios WHERE email = ?', [email]);
        if (users.length === 0 || users[0].token_email !== code) return res.status(400).json({ message: 'Código incorrecto.' });
        await db.query('UPDATE usuarios SET estado_cuenta = ?, token_email = NULL WHERE id = ?', ['activo', users[0].id]);
        res.status(200).json({ message: 'Cuenta activada.' });
    } catch (error) { res.status(500).json({ message: 'Error.' }); }
});

router.post('/forgot-password', recoveryLimiter, async (req, res) => {
    /* (Mismo código de antes) */
    try {
        const { email } = req.body;
        const [users] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);
        if (users.length > 0) {
            const user = users[0];
            const resetToken = Math.floor(100000 + Math.random() * 900000).toString();
            await db.query('UPDATE usuarios SET reset_token = ?, reset_token_expires = (UTC_TIMESTAMP() + INTERVAL 10 MINUTE) WHERE id = ?', [resetToken, user.id]);
            await sendPasswordResetEmail(user.email, resetToken);
        }
        res.status(200).json({ message: 'Si existe, se envió el código.' });
    } catch (error) { res.status(500).json({ message: 'Error.' }); }
});

router.post('/get-question', async (req, res) => { /* (Igual que antes) */
    try {
        const { email } = req.body;
        const [users] = await db.query('SELECT pregunta_secreta FROM usuarios WHERE email = ?', [email]);
        if (users.length === 0 || !users[0].pregunta_secreta) return res.status(404).json({ message: 'Usuario no encontrado.' });
        res.status(200).json({ pregunta: users[0].pregunta_secreta });
    } catch (error) { res.status(500).json({ message: 'Error.' }); }
});

router.post('/recover-by-question', async (req, res) => { /* (Igual que antes) */
    try {
        const { email, respuesta } = req.body;
        const [users] = await db.query('SELECT id, respuesta_secreta FROM usuarios WHERE email = ?', [email]);
        if (users.length === 0 || !users[0].respuesta_secreta) return res.status(400).json({ message: 'Datos incorrectos.' });
        const isMatch = await bcrypt.compare(respuesta.toLowerCase().trim(), users[0].respuesta_secreta);
        if (!isMatch) return res.status(400).json({ message: 'Respuesta incorrecta.' });
        const resetToken = Math.floor(100000 + Math.random() * 900000).toString();
        await db.query('UPDATE usuarios SET reset_token = ?, reset_token_expires = (UTC_TIMESTAMP() + INTERVAL 10 MINUTE) WHERE id = ?', [resetToken, users[0].id]);
        res.status(200).json({ message: 'Correcto.', resetToken });
    } catch (error) { res.status(500).json({ message: 'Error.' }); }
});

router.post('/verify-reset-code', async (req, res) => { /* (Igual que antes) */
    try {
        const { email, code } = req.body;
        const [users] = await db.query('SELECT id FROM usuarios WHERE email = ? AND reset_token = ? AND reset_token_expires > UTC_TIMESTAMP()', [email, code]);
        if (users.length === 0) return res.status(400).json({ message: 'Código inválido.' });
        res.status(200).json({ message: 'Código correcto.' });
    } catch (error) { res.status(500).json({ message: 'Error.' }); }
});

router.post('/reset-password', async (req, res) => { /* (Igual que antes) */
    try {
        const { email, code, password } = req.body;
        const [users] = await db.query('SELECT id FROM usuarios WHERE email = ? AND reset_token = ? AND reset_token_expires > UTC_TIMESTAMP()', [email, code]);
        if (users.length === 0) return res.status(400).json({ message: 'Código inválido.' });
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        await db.query('UPDATE usuarios SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?', [hashedPassword, users[0].id]);
        res.status(200).json({ message: 'Contraseña actualizada.' });
    } catch (error) { res.status(500).json({ message: 'Error.' }); }
});

module.exports = router;