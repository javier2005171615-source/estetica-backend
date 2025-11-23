const twilio = require('twilio');

// 1. Cargar las variables de entorno
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const twilioPhone = process.env.TWILIO_PHONE_NUMBER;

// 2. Inicializar el cliente de Twilio
const client = twilio(accountSid, authToken);

// 3. Función para dar formato al número (¡MUY IMPORTANTE!)
// Twilio requiere el formato E.164 (ej: +521234567890)
// Asumiremos números de México (prefijo +52). Ajusta si es necesario.
const formatPhoneE164 = (phone) => {
  // Quitar espacios, paréntesis, etc.
  let cleanPhone = phone.replace(/[\s\-\(\)]/g, '');

  // Si tiene 10 dígitos (ej. 5512345678), asumimos que es de México
  // y le añadimos el prefijo +52
  if (cleanPhone.length === 10) {
    return `+52${cleanPhone}`;
  }
  
  // Si ya tiene el +52, lo dejamos como está
  if (cleanPhone.startsWith('+52') && cleanPhone.length === 13) {
    return cleanPhone;
  }

  // Devolver el número tal cual si no coincide (puede fallar si está mal formateado)
  return cleanPhone;
};


// 4. Función para enviar el SMS de verificación
const sendVerificationSms = async (userPhone, code) => {
  try {
    const formattedPhone = formatPhoneE164(userPhone);
    
    await client.messages.create({
      body: `Tu código de verificación para Mi Estética es: ${code}`,
      from: twilioPhone, // Tu número de Twilio
      to: formattedPhone    // El número del usuario (formateado)
    });

    console.log(`SMS de verificación enviado a: ${formattedPhone}`);
  
  } catch (error) {
    // Es muy común que falle aquí si el número de 'to'
    // no está verificado en tu cuenta de prueba de Twilio.
    console.error(`Error al enviar SMS a ${userPhone}:`, error.message);
  }
};

// Exportamos la función
module.exports = {
  sendVerificationSms
};