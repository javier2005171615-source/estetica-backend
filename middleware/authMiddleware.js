const jwt = require('jsonwebtoken');
const db = require('../db');

// Guardián Básico (Lee Cookie)
const checkAuth = async (req, res, next) => {
  try {
    // CAMBIO: Leemos el token desde la COOKIE
    const token = req.cookies.token; 

    if (!token) {
      return res.status(401).json({ message: 'No autorizado. Inicia sesión.' });
    }

    // Verificar Lista Negra
    const [blacklisted] = await db.query(
      'SELECT id FROM token_blacklist WHERE token = ?',
      [token]
    );

    if (blacklisted.length > 0) {
      return res.status(401).json({ message: 'Sesión invalidada.' });
    }

    // Verificar Token
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decodedToken; 
    next();

  } catch (error) {
    return res.status(401).json({ message: 'Token no válido o expirado.' });
  }
};

const checkAdmin = (req, res, next) => {
  if (req.user && req.user.tipo_usuario === 'admin') {
    next(); 
  } else {
    res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
  }
};

module.exports = { checkAuth, checkAdmin };