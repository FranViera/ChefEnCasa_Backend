const bcrypt = require('bcryptjs');
const { ObjectId } = require('mongodb');

// Definir el esquema de usuario
const UserSchema = {
  _id: ObjectId,
  nombre: String,
  email: String,
  password: String,
  telefono: {
    prefijo: String, // Prefijo del país
    numero: String, // Número de teléfono
  },
  healthData: {
    weight: Number,
    height: Number,
    imc: Number,
    dietRecommendation: String,
    caloricNeeds: Number, // Calorías diarias recomendadas
    tmb: Number,          // Tasa Metabólica Basal
  },
  policiesAccepted: {
    type: Boolean,
    default: false,
  },
  premium: {
    type: Boolean,
    default: false, // Los usuarios no serán premium por defecto
  },
};

// Función para hashear la contraseña
async function hashPassword(password) {
  const salt = await bcrypt.genSalt(10);
  return await bcrypt.hash(password, salt);
}

// Función para verificar la contraseña
async function comparePassword(plainPassword, hashedPassword) {
  return await bcrypt.compare(plainPassword, hashedPassword);
}

module.exports = { UserSchema, hashPassword, comparePassword };
