const express = require('express');
require('dotenv').config();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const cors = require('cors');
const app = express();
app.use(express.json());
app.use(cors());


const MONGODB_URI = 'mongodb://127.0.0.1:27017/ElectricDigitalApp';

mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('Conectado a MongoDB'))
.catch(err => console.error('Error conectando a MongoDB:', err));


///////////////////////////////////////////////////////////////////SCHEMAS///////////////////////////////////////////////////////////////////
const userSchema = new Schema({
    nombres: String,
    apellidos: String,
    fechaNacimiento: Date,
    sexo: String,
    estadoCivil: String,
    rut: String,
    direccion: String,
    cargo: String,
    email: { type: String, unique: true },
    telefono: String,
    password: String,
    isAdmin: { type: Boolean, default: false }
});
const User = mongoose.model('User', userSchema);
///////////////////////////////////////////////////////////////////SCHEMAS///////////////////////////////////////////////////////////////////

const SECRET_KEY = process.env.JWT_SECRET; 
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: 'Token requerido' });
    jwt.verify(token, SECRET_KEY, (err, user) => {
      if (err) return res.status(403).json({ error: 'Token inválido' });
      req.user = user;
      next();
    });
};

app.post('/api/register', async (req, res) => {
    const { 
        nombres,
        apellidos,
        fechaNacimiento,
        sexo,
        estadoCivil,
        rut,
        direccion,
        cargo,
        email,
        telefono,
        password 
    } = req.body;

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'El correo electrónico ya está registrado' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            nombres,
            apellidos,
            fechaNacimiento,
            sexo,
            estadoCivil,
            rut,
            direccion,
            cargo,
            email,
            telefono,
            password: hashedPassword
        });

        await user.save();
        res.status(201).send('Usuario registrado con éxito');
    } catch (error) {
        res.status(500).send('Error al registrar el usuario: ' + error.message);
    }
});



app.post('/api/login', async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email });
        if (!user) {
            return res.status(400).send('Usuario no encontrado');
        }

        const validPassword = await bcrypt.compare(req.body.password, user.password);
        if (!validPassword) {
            return res.status(400).send('Contraseña incorrecta');
        }

        const token = jwt.sign({ userId: user._id }, SECRET_KEY, { expiresIn: '1h' });

        res.send({
            message: 'Inicio de sesión exitoso',
            token: token
        });
    } catch (error) {
        res.status(500).send('Error al iniciar sesión: ' + error.message);
    }
});


app.get('/api/checkTokenValidity', verifyToken, (req, res) => {
    // Si el middleware verifyToken no envió un error, entonces el token es válido
    res.status(200).json({ valid: true });
  });  




const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});

