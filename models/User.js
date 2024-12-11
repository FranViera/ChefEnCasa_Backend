const bcrypt = require('bcryptjs');
const { ObjectId } = require('mongodb');

// Definir el esquema de usuario
const UserSchema = {
  _id: ObjectId,
  nombre: String,
  email: String,
  password: String,
  telefono: {
    prefijo: String,
    numero: String,
  },
  points: {
    type: Number,
    default: 0, // Inicialmente 0 puntos
  },
  fechaUltimaActualizacionPuntos: {
    type: Date,
    default: new Date(), // Control de la última vez que se sumaron puntos
  },
  healthData: {
    weight: Number,
    height: Number,
    imc: Number,
    dietRecommendation: String,
    caloricNeeds: Number,
    tmb: Number,
  },
  policiesAccepted: {
    type: Boolean,
    default: false,
  },
  premium: {
    status: {
      type: Boolean,
      default: false,
    },
    fechaInicio: Date,
    fechaFin: Date,
  },
  fechaRegistro: {
    type: Date,
    default: new Date(),
  },
  fechaUltimaSesion: {
    type: Date,
    default: null,
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
