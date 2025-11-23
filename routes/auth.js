const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const db = require('../db');

// Importamos servicios de correo (YA NO usamos smsService)
const { sendVerificationEmail, sendPasswordResetEmail, sendLockoutWarningEmail } = require('../services/mailService');

// Importamos Google Auth
const { OAuth2Client } = require('google-auth-library');
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Importamos validaciones
const { body, validationResult } = require('express-validator');

const rateLimit = require('express-rate-limit');


// Permite solo 3 solicitudes cada hora por IP
const recoveryLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hora
  max: 3, // Límite de 3 peticiones
  message: { message: 'Has excedido el límite de solicitudes. Inténtalo de nuevo en una hora.' },
  standardHeaders: true, // Devuelve información del límite en las cabeceras `RateLimit-*`
  legacyHeaders: false, // Deshabilita las cabeceras `X-RateLimit-*`
});

// --- REGLAS DE VALIDACIÓN PARA REGISTRO ---
const registerValidationRules = [
  body('nombre').trim().escape(),
  body('apellidos').trim().escape(),
  body('email').isEmail().withMessage('Email inválido').normalizeEmail(),
  body('telefono').trim().escape(),
  body('password')
    .isLength({ min: 8 }).withMessage('Mínimo 8 caracteres')
    .matches(/[A-Z]/).withMessage('Debe tener mayúscula')
    .matches(/[a-z]/).withMessage('Debe tener minúscula')
    .matches(/\d/).withMessage('Debe tener número'),
  // Validamos pregunta y respuesta
  body('preguntaSecreta').trim().notEmpty().withMessage('Selecciona una pregunta secreta'),
  body('respuestaSecreta').trim().notEmpty().withMessage('La respuesta secreta es obligatoria').escape()
];


// ==========================================
// 1. RUTA DE REGISTRO
// ==========================================
router.post('/register', registerValidationRules, async (req, res) => {
  // 1. Revisar errores de validación
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ message: errors.array()[0].msg });
  }

  try {
    const { nombre, apellidos, telefono, email, password, preguntaSecreta, respuestaSecreta } = req.body;

    // 2. Verificar si ya existe
    const [existingUser] = await db.query('SELECT id FROM usuarios WHERE email = ?', [email]);
    if (existingUser.length > 0) {
      return res.status(409).json({ message: 'El correo ya está registrado.' });
    }

    // 3. Encriptar Contraseña Y Respuesta Secreta
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    // Normalizamos la respuesta a minúsculas antes de hashear para que no importen las mayúsculas al recuperar
    const hashedAnswer = await bcrypt.hash(respuestaSecreta.toLowerCase().trim(), salt);

    // 4. Generar Token de Activación
    const emailToken = Math.floor(100000 + Math.random() * 900000).toString();

    // 5. Insertar en Base de Datos
    const sql = `
      INSERT INTO usuarios 
      (nombre, apellidos, telefono, email, password, pregunta_secreta, respuesta_secreta, token_email) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;
    
    await db.query(sql, [
      nombre, apellidos, telefono, email, hashedPassword, 
      preguntaSecreta, hashedAnswer, emailToken
    ]);

    // 6. Enviar Correo
    await sendVerificationEmail(email, emailToken);

    res.status(201).json({ message: '¡Registro exitoso! Revisa tu email para activar tu cuenta.' });

  } catch (error) {
    console.error('Error en /register:', error);
    res.status(500).json({ message: 'Error en el servidor.' });
  }
});


// ==========================================
// 2. RUTA DE LOGIN (Con Bloqueo)
// ==========================================
router.post('/login', async (req, res) => {
  try {
    const { email, password, rol } = req.body;

    if (!email || !password || !rol) {
      return res.status(400).json({ message: 'Faltan credenciales.' });
    }

    const [users] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);
    if (users.length === 0) return res.status(401).json({ message: 'Credenciales inválidas.' });

    const user = users[0];

    // A. Revisar si está bloqueado
    const [lockStatus] = await db.query(
      'SELECT (lockout_expires > UTC_TIMESTAMP()) AS is_locked FROM usuarios WHERE id = ?',
      [user.id]
    );

    if (lockStatus[0].is_locked) {
      return res.status(429).json({ message: 'Cuenta bloqueada. Inténtalo de nuevo en 5 minutos.' });
    }
    // --- ¡AQUÍ ESTÁ LA CORRECCIÓN! ---
    // Si el usuario NO tiene contraseña (es de Google), no podemos usar bcrypt
    if (!user.password) {
      return res.status(400).json({ 
        message: 'Esta cuenta se registró con Google. Por favor, inicia sesión con el botón de Google.' 
      });
    }

    // B. Verificar Contraseña
    const isMatch = await bcrypt.compare(password, user.password);

    if (isMatch) {
      // Login Exitoso
      if (user.tipo_usuario !== rol) return res.status(401).json({ message: 'Rol incorrecto.' });
      if (user.estado_cuenta === 'pendiente') return res.status(403).json({ message: 'Cuenta no activada.' });

      // Resetear intentos fallidos
      await db.query('UPDATE usuarios SET login_attempts = 0, lockout_expires = NULL WHERE id = ?', [user.id]);

      const token = jwt.sign({ userId: user.id, email: user.email, tipo_usuario: user.tipo_usuario }, process.env.JWT_SECRET, { expiresIn: '1d' });

      return res.status(200).json({
        message: 'Inicio de sesión exitoso.',
        token: token,
        user: { id: user.id, nombre: user.nombre, email: user.email, tipo_usuario: user.tipo_usuario }
      });

    } else {
      // Login Fallido
      const newAttempts = user.login_attempts + 1;
      if (newAttempts >= 3) {
        // Bloquear por 5 minutos
        await db.query('UPDATE usuarios SET login_attempts = ?, lockout_expires = (UTC_TIMESTAMP() + INTERVAL 5 MINUTE) WHERE id = ?', [newAttempts, user.id]);
        await sendLockoutWarningEmail(user.email);
        return res.status(429).json({ message: 'Demasiados intentos. Cuenta bloqueada por 5 minutos.' });
      } else {
        // Incrementar contador
        await db.query('UPDATE usuarios SET login_attempts = ? WHERE id = ?', [newAttempts, user.id]);
        return res.status(401).json({ message: `Credenciales inválidas. Intentos restantes: ${3 - newAttempts}` });
      }
    }

  } catch (error) {
    console.error('Error en /login:', error);
    res.status(500).json({ message: 'Error en el servidor.' });
  }
});


// ==========================================
// 3. RUTAS DE RECUPERACIÓN DE CONTRASEÑA
// ==========================================

// A. Solicitar Código por Correo
// Añadimos 'recoveryLimiter' aquí
router.post('/forgot-password', recoveryLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    const [users] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);
    
    if (users.length > 0) {
      const user = users[0];
      const resetToken = Math.floor(100000 + Math.random() * 900000).toString();
      
      await db.query(
        'UPDATE usuarios SET reset_token = ?, reset_token_expires = (UTC_TIMESTAMP() + INTERVAL 10 MINUTE) WHERE id = ?',
        [resetToken, user.id]
      );
      await sendPasswordResetEmail(user.email, resetToken);
    }
    // Siempre respondemos lo mismo por seguridad
    res.status(200).json({ message: 'Si el correo existe, se ha enviado un código.' });

  } catch (error) {
    res.status(500).json({ message: 'Error en el servidor.' });
  }
});

// B. Obtener Pregunta Secreta (Paso 1 de Método Pregunta)
router.post('/get-question', async (req, res) => {
  try {
    const { email } = req.body;
    const [users] = await db.query('SELECT pregunta_secreta FROM usuarios WHERE email = ?', [email]);
    
    if (users.length === 0 || !users[0].pregunta_secreta) {
      return res.status(404).json({ message: 'Usuario no encontrado o sin pregunta configurada.' });
    }
    res.status(200).json({ pregunta: users[0].pregunta_secreta });
  } catch (error) {
    res.status(500).json({ message: 'Error.' });
  }
});

// C. Verificar Respuesta Secreta (Paso 2 de Método Pregunta)
router.post('/recover-by-question', async (req, res) => {
  try {
    const { email, respuesta } = req.body;
    const [users] = await db.query('SELECT id, respuesta_secreta FROM usuarios WHERE email = ?', [email]);

    if (users.length === 0 || !users[0].respuesta_secreta) {
      return res.status(400).json({ message: 'Datos incorrectos.' });
    }
    const user = users[0];
    const isMatch = await bcrypt.compare(respuesta.toLowerCase().trim(), user.respuesta_secreta);

    if (!isMatch) return res.status(400).json({ message: 'Respuesta incorrecta.' });

    // Generamos token para permitir el cambio de contraseña
    const resetToken = Math.floor(100000 + Math.random() * 900000).toString();
    await db.query(
      'UPDATE usuarios SET reset_token = ?, reset_token_expires = (UTC_TIMESTAMP() + INTERVAL 10 MINUTE) WHERE id = ?',
      [resetToken, user.id]
    );

    res.status(200).json({ message: 'Correcto.', resetToken });

  } catch (error) {
    res.status(500).json({ message: 'Error.' });
  }
});

// D. Verificar Código de Correo (Paso 2 de Método Correo)
router.post('/verify-reset-code', async (req, res) => {
  try {
    const { email, code } = req.body;
    const [users] = await db.query(
      'SELECT id FROM usuarios WHERE email = ? AND reset_token = ? AND reset_token_expires > UTC_TIMESTAMP()',
      [email, code]
    );
    if (users.length === 0) return res.status(400).json({ message: 'Código inválido o expirado.' });
    res.status(200).json({ message: 'Código correcto.' });
  } catch (error) {
    res.status(500).json({ message: 'Error.' });
  }
});

// E. Reestablecer Contraseña (Final para ambos métodos)
router.post('/reset-password', async (req, res) => {
  try {
    const { email, code, password } = req.body;
    const [users] = await db.query(
      'SELECT id FROM usuarios WHERE email = ? AND reset_token = ? AND reset_token_expires > UTC_TIMESTAMP()',
      [email, code]
    );

    if (users.length === 0) return res.status(400).json({ message: 'Sesión expirada. Inicia el proceso de nuevo.' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    await db.query(
      'UPDATE usuarios SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?',
      [hashedPassword, users[0].id]
    );
    res.status(200).json({ message: 'Contraseña actualizada.' });

  } catch (error) {
    res.status(500).json({ message: 'Error.' });
  }
});


// ==========================================
// 4. RUTAS ADICIONALES (Activar cuenta, Google)
// ==========================================
router.post('/verify-code', async (req, res) => {
  try {
    const { email, code } = req.body;
    const [users] = await db.query('SELECT id, token_email FROM usuarios WHERE email = ?', [email]);
    if (users.length === 0) return res.status(404).json({ message: 'Usuario no encontrado.' });
    if (users[0].token_email !== code) return res.status(400).json({ message: 'Código incorrecto.' });
    await db.query('UPDATE usuarios SET estado_cuenta = ?, token_email = NULL WHERE id = ?', ['activo', users[0].id]);
    res.status(200).json({ message: 'Cuenta activada.' });
  } catch (error) {
    res.status(500).json({ message: 'Error.' });
  }
});

// --- RUTA: LOGIN CON GOOGLE (CORREGIDA) ---
router.post('/google-login', async (req, res) => {
  const { credential } = req.body; 

  try {
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    
    const payload = ticket.getPayload();
    const { email, given_name, family_name } = payload; 

    let [users] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);
    let user;

    if (users.length === 0) {
      console.log('Creando nuevo usuario de Google...');
      
      // --- CORRECCIÓN AQUÍ ---
      // Usamos desestructuración [result] para obtener el objeto correcto
      const [result] = await db.query(
        `INSERT INTO usuarios (nombre, apellidos, email, tipo_usuario, estado_cuenta) 
         VALUES (?, ?, ?, 'cliente', 'activo')`,
        [given_name, family_name || '', email]
      );
      
      // Usamos result.insertId
      [users] = await db.query('SELECT * FROM usuarios WHERE id = ?', [result.insertId]);
      // -----------------------
    }
    
    user = users[0];

    // Validación extra por si algo falló al crear el usuario
    if (!user) {
      return res.status(500).json({ message: 'Error al crear o recuperar usuario de Google.' });
    }

    if (user.estado_cuenta === 'pendiente') {
        await db.query('UPDATE usuarios SET estado_cuenta = ? WHERE id = ?', ['activo', user.id]);
        user.estado_cuenta = 'activo';
    }

    // Revisar si la cuenta de Google está bloqueada por intentos fallidos
    const [lockStatus] = await db.query(
      'SELECT (lockout_expires > UTC_TIMESTAMP()) AS is_locked FROM usuarios WHERE id = ?',
      [user.id]
    );

    if (lockStatus[0] && lockStatus[0].is_locked) {
      return res.status(429).json({ message: 'Esta cuenta está bloqueada temporalmente. Inténtalo de nuevo en 5 minutos.' });
    }
    
    // Si no está bloqueada, limpiamos intentos por si acaso
    await db.query('UPDATE usuarios SET login_attempts = 0, lockout_expires = NULL WHERE id = ?', [user.id]);

    // Crear NUESTRO PROPIO token (JWT)
    const jwtPayload = {
      userId: user.id,
      email: user.email,
      tipo_usuario: user.tipo_usuario
    };
    const token = jwt.sign(jwtPayload, process.env.JWT_SECRET, { expiresIn: '1d' });

    res.status(200).json({
      message: 'Inicio de sesión con Google exitoso.',
      token: token,
      user: {
        id: user.id,
        nombre: user.nombre,
        email: user.email,
        tipo_usuario: user.tipo_usuario
      }
    });

  } catch (error) {
    console.error('Error en /google-login:', error);
    res.status(401).json({ message: 'Autenticación con Google fallida.' });
  }
});

module.exports = router;