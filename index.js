require('dotenv').config(); 

const express = require('express');
const cors = require('cors');
const db = require('./db'); 
const helmet = require('helmet'); 
const morgan = require('morgan'); 
const cookieParser = require('cookie-parser');
const https = require("https");
const fs = require("fs");
const path = require('path');

const authRoutes = require('./routes/auth');

const app = express();
const port = process.env.PORT || 5000; // Vercel asignará su propio puerto

// --- MIDDLEWARES ---
// En producción (Vercel), el origen cambiará. Por ahora permitimos todo o configuramos dinámicamente.
// Cuando subas el frontend, cambiarás este origin por la URL de Netlify.
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? process.env.FRONTEND_URL // Leerá esto de las variables de Vercel
    : 'https://localhost:3000',
  credentials: true 
}));

app.use(
  helmet({
    crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" },
    crossOriginResourcePolicy: { policy: "cross-origin" },
    referrerPolicy: { policy: "no-referrer-when-downgrade" },
    contentSecurityPolicy: false,
  })
);

app.use(express.json());
app.use(cookieParser());
app.use(morgan('dev')); 

// Rutas
app.use('/api/auth', authRoutes); 

app.get('/', (req, res) => {
  res.send('¡API de Estética Funcionando en la Nube! 🚀');
});

// --- ARRANCAR EL SERVIDOR (Lógica Híbrida) ---

if (process.env.NODE_ENV === 'production') {
  // --- MODO NUBE (VERCEL) ---
  // En Vercel no usamos certificados manuales, Vercel se encarga.
  // Solo exportamos la app o escuchamos en puerto estándar HTTP.
  app.listen(port, () => {
    console.log(`🚀 Servidor Nube corriendo en el puerto ${port}`);
  });
} else {
  // --- MODO LOCAL (TU PC) ---
  // Aquí sí usamos tus certificados mkcert para HTTPS
  try {
    const key = fs.readFileSync(path.join(__dirname, 'certs', 'localhost-key.pem'));
    const cert = fs.readFileSync(path.join(__dirname, 'certs', 'localhost.pem'));
    
    https.createServer({ key, cert }, app).listen(port, () => {
      console.log(`🔒 Servidor LOCAL SEGURO en https://localhost:${port}`);
    });
  } catch (error) {
    console.error("No se encontraron certificados. Iniciando en modo HTTP inseguro (fallback).");
    app.listen(port, () => console.log(`⚠️ Servidor HTTP en http://localhost:${port}`));
  }
}

// Necesario para Vercel Serverless
module.exports = app;