require('dotenv').config(); 

const express = require('express');
const cors = require('cors');
const db = require('./db'); 
const helmet = require('helmet'); 
const https = require("https");
const fs = require("fs");
// Agregamos morgan para ver los logs (opcional pero recomendado)
const morgan = require('morgan'); 

const authRoutes = require('./routes/auth');

const app = express();
const port = 5000; // <-- Este es el puerto correcto

// Carga de certificados desde tu ruta absoluta
const key = fs.readFileSync("C:/mkcert/localhost-key.pem");
const cert = fs.readFileSync("C:/mkcert/localhost.pem");

// Middlewares
app.use(cors()); 
app.use(
  helmet({
    crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" },
    crossOriginResourcePolicy: { policy: "cross-origin" },
    referrerPolicy: { policy: "no-referrer-when-downgrade" },
    contentSecurityPolicy: false,
  })
);
app.use(express.json());
app.use(morgan('dev')); // Logs en consola

// Rutas
app.use('/api/auth', authRoutes); 

app.get('/', (req, res) => {
  res.send('¡Bienvenido a la API de la Estética Segura!');
});

app.get('/test-db', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT 1 + 1 AS solution');
    res.json({
      success: true,
      message: '¡Conexión a la base de datos exitosa!',
      result: rows[0].solution
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error al conectar con la base de datos.',
      error: error.message
    });
  }
});

// --- INICIAR SERVIDOR ---
// Usamos la variable 'port' (5000) en lugar de escribir 3000
https.createServer({ key, cert }, app).listen(port, () => {
  console.log(`🔒 Servidor SEGURO corriendo en https://localhost:${port}`);
});