// Carga las variables de entorno del archivo .env
require('dotenv').config();

// Importa el paquete mysql2 que ya instalamos
const mysql = require('mysql2');

// Crea un "pool" de conexiones
// Un pool es más eficiente que una sola conexión
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Exportamos el pool "promisificado" para usar async/await (más moderno)
module.exports = pool.promise();