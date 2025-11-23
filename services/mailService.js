const nodemailer = require('nodemailer');

// 1. Configurar el "transporter" (el servicio que envía)
const transporter = nodemailer.createTransport({
  service: 'gmail', // Vamos a usar Gmail
  auth: {
    user: process.env.EMAIL_USER, // Tu correo de .env
    pass: process.env.EMAIL_PASS  // Tu contraseña de app de .env
  }
});

// 2. Función para enviar el correo de verificación
const sendVerificationEmail = async (userEmail, token) => {
  // Opciones del correo
  const mailOptions = {
    from: `"Mi Estética" <${process.env.EMAIL_USER}>`,
    to: userEmail,
    subject: 'Tu código de verificación para Mi Estética',
    
    // Cuerpo del correo
    html: `
      <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px;">
        <h2>¡Bienvenido/a a Mi Estética!</h2>
        <p>Gracias por registrarte. Usa el siguiente código para activar tu cuenta:</p>
        <h1 style="font-size: 48px; letter-spacing: 10px; margin: 20px; color: #ad1457;">
          ${token}
        </h1>
        <p>Si no te registraste, por favor ignora este correo.</p>
      </div>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Código de verificación enviado a: ${userEmail}`);
  } catch (error) {
    console.error(`Error al enviar correo a ${userEmail}:`, error);
  }
};


// 3. --- FUNCIÓN PARA RESETEAR CONTRASEÑA ---
const sendPasswordResetEmail = async (userEmail, token) => {
  const mailOptions = {
    from: `"Mi Estética" <${process.env.EMAIL_USER}>`,
    to: userEmail,
    subject: 'Tu código de recuperación de contraseña',
    html: `
      <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px;">
        <h2>Recuperación de Contraseña</h2>
        <p>Usa el siguiente código para reestablecer tu contraseña. Si no lo solicitaste, ignora este correo.</p>
        <h1 style="font-size: 48px; letter-spacing: 10px; margin: 20px; color: #ad1457;">
          ${token}
        </h1>
        <p>Este código expirará en 10 minutos.</p>
      </div>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Correo de reseteo enviado a: ${userEmail}`);
  } catch (error) {
    console.error(`Error al enviar correo de reseteo a ${userEmail}:`, error);
  }
};

// --- NUEVA FUNCIÓN PARA ADVERTIR DE BLOQUEO ---
const sendLockoutWarningEmail = async (userEmail) => {
  const mailOptions = {
    from: `"Mi Estética" <${process.env.EMAIL_USER}>`,
    to: userEmail,
    subject: 'Alerta de Seguridad: Cuenta bloqueada temporalmente',
    html: `
      <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px;">
        <h2>Alerta de Seguridad de Mi Estética</h2>
        <p>Hemos detectado 3 intentos fallidos de inicio de sesión en tu cuenta.</p>
        <p>Como medida de seguridad, <strong>tu cuenta ha sido bloqueada por 5 minutos</strong>.</p>
        <p>Si no fuiste tú quien intentó iniciar sesión, te recomendamos asegurar tu cuenta o reestablecer tu contraseña.</p>
      </div>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Correo de advertencia de bloqueo enviado a: ${userEmail}`);
  } catch (error) {
    console.error(`Error al enviar correo de bloqueo a ${userEmail}:`, error);
  }
};


// 4. --- EXPORTACIÓN CORRECTA ---
// --- EXPORTACIÓN CORRECTA ---
module.exports = {
  sendVerificationEmail,
  sendPasswordResetEmail,
  sendLockoutWarningEmail // <-- ¡AÑADE ESTA LÍNEA!
};