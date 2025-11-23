const jwt = require('jsonwebtoken');

// 1. Guardián Básico: Revisa si el token es válido
const checkAuth = (req, res, next) => {
  try {
    // Buscamos el token en los headers
    // (Debe venir como "Bearer eyJhbGciOi...")
    const token = req.headers.authorization.split(' ')[1]; 
    
    if (!token) {
      return res.status(401).json({ message: 'No hay token, autorización denegada' });
    }

    // Verificamos el token con nuestro secreto
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    
    // Guardamos los datos del usuario (id, rol) en la request
    // para que las siguientes rutas puedan usarlo
    req.user = decodedToken; 
    next(); // El token es válido, continúa

  } catch (error) {
    res.status(401).json({ message: 'Token no es válido' });
  }
};

// 2. Guardián de Rol: Revisa si es Admin
const checkAdmin = (req, res, next) => {
  // Este guardián debe usarse *después* de checkAuth
  if (req.user && req.user.tipo_usuario === 'admin') {
    next(); // Es admin, puede pasar
  } else {
    res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
  }
};

module.exports = { checkAuth, checkAdmin };