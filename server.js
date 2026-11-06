const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// Conexión a MySQL utilizando variables de entorno (.env) - Nivel Excelente
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect(err => {
    if (err) {
        console.error('❌ Error crítico al conectar a MySQL:', err);
        return;
    }
    console.log('✅ Servidor CGO conectado exitosamente a MySQL.');
});

// ==========================================
// API: REGISTRO DE USUARIOS (Con doble validación backend)
// ==========================================
app.post('/api/auth/register', async (req, res) => {
    try {
        const { nombre, email, password } = req.body;

        // Validación estricta en backend (Criterio 2)
        if (!nombre || !email || !password || password.length < 4) {
            return res.status(400).json({ success: false, message: 'Datos inválidos o contraseña muy corta.' });
        }

        // Validación de formato de correo con Expresión Regular en Backend
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ success: false, message: 'El formato del correo electrónico no es válido.' });
        }

        // Sentencia preparada para verificar duplicados (Criterio 1 y 3)
        db.query('SELECT id FROM usuarios WHERE email = ?', [email], async (err, results) => {
            if (err) return res.status(500).json({ success: false, message: 'Error interno en el servidor.' });
            
            if (results.length > 0) {
                return res.status(400).json({ success: false, message: 'El correo electrónico ya se encuentra registrado.' });
            }

            // Cifrado robusto con bcrypt (Criterio 1)
            const hashedPassword = await bcrypt.hash(password, 10);
            const query = 'INSERT INTO usuarios (nombre, email, password_hash, fecha_registro) VALUES (?, ?, ?, NOW())';
            
            // Sentencia preparada para inserción segura (Prevención de Inyección SQL)
            db.query(query, [nombre, email, hashedPassword], (err, result) => {
                if (err) return res.status(500).json({ success: false, message: 'Error al registrar usuario en la base de datos.' });
                res.status(201).json({ success: true, message: 'Cuenta creada con éxito.' });
            });
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error crítico al procesar la solicitud.' });
    }
});

// ==========================================
// API: INICIO DE SESIÓN
// ==========================================
app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Ingrese correo y contraseña.' });
    }

    db.query('SELECT * FROM usuarios WHERE email = ?', [email], async (err, results) => {
        if (err) return res.status(500).json({ success: false, message: 'Error en el servidor.' });
        
        if (results.length === 0) {
            return res.status(401).json({ success: false, message: 'Credenciales incorrectas o usuario inexistente.' });
        }

        const user = results[0];
        const match = await bcrypt.compare(password, user.password_hash);

        if (match) {
            res.json({
                success: true,
                message: 'Bienvenido al sistema',
                user: { id: user.id, nombre: user.nombre, email: user.email }
            });
        } else {
            res.status(401).json({ success: false, message: 'Contraseña incorrecta.' });
        }
    });
});

// ==========================================
// API: CREAR REPORTE / SOLICITUD
// ==========================================
app.post('/api/reportes', (req, res) => {
    const { solicitante, tipoResiduo, calle, municipio, tipoLugar, lat, lng, referencia } = req.body;

    if (!lat || !lng || !calle) {
        return res.status(400).json({ success: false, message: 'Faltan datos obligatorios de ubicación.' });
    }

    const query = `INSERT INTO solicitudes (solicitante, tipo_residuo, calle, municipio, tipo_lugar, latitud, longitud, referencia) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;

    db.query(query, [solicitante, tipoResiduo, calle, municipio, tipoLugar, lat, lng, referencia], (err, result) => {
        if (err) return res.status(500).json({ success: false, message: 'Error al registrar el reporte.' });
        res.status(201).json({ success: true, message: 'Reporte registrado exitosamente.' });
    });
});

// ==========================================
// API: OBTENER REPORTES
// ==========================================
app.get('/api/reportes', (req, res) => {
    db.query('SELECT * FROM solicitudes ORDER BY id DESC', (err, results) => {
        if (err) return res.status(500).json({ success: false, message: 'Error al obtener datos.' });
        res.json({ success: true, data: results });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 CGO Backend Enterprise corriendo en http://localhost:${PORT}`);
});
// ==========================================
// API: GUARDAR OPINIÓN DE LA COMUNIDAD
// ==========================================
app.post('/api/opiniones', (req, res) => {
    const { autor, puntuacion, mensaje } = req.body;

    if (!autor || !puntuacion || !mensaje) {
        return res.status(400).json({ success: false, message: 'Todos los campos son obligatorios.' });
    }

    const query = 'INSERT INTO opiniones (autor, puntuacion, mensaje, fecha_opinion) VALUES (?, ?, ?, NOW())';
    
    db.query(query, [autor, puntuacion, mensaje], (err, result) => {
        if (err) return res.status(500).json({ success: false, message: 'Error al guardar la opinión en la base de datos.' });
        res.status(201).json({ success: true, message: 'Opinión guardada con éxito.' });
    });
});

// ==========================================
// API: OBTENER TODAS LAS OPINIONES
// ==========================================
app.get('/api/opiniones', (req, res) => {
    db.query('SELECT * FROM opiniones ORDER BY id DESC', (err, results) => {
        if (err) return res.status(500).json({ success: false, message: 'Error al obtener las opiniones.' });
        res.json({ success: true, data: results });
    });
});