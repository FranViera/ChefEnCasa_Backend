// Importar dependencias necesarias
const express = require('express');
const { MongoClient, ServerApiVersion } = require('mongodb');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const swaggerJsDoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const Joi = require('joi');
const morgan = require('morgan');
const winston = require('winston');
const NodeCache = require('node-cache');
const { ObjectId } = require('mongodb');
const fs = require('fs'); // Importar el módulo de sistema de archivos (fs)
const Almacen = require('./models/Almacen');
const { crearOActualizarAlmacen } = require('./models/Almacen'); // Importar las funciones actualizadas de Almacen.js
const { getNoticias } = require('./models/newsService');
const path = require('path');
require('dotenv').config();

// Cargar las variables de entorno desde el archivo .env
dotenv.config();

// Inicializar la aplicación Express
const app = express();
app.use(express.json());

// Usar Helmet para aumentar la seguridad agregando encabezados HTTP seguros
app.use(helmet());

// Límite de peticiones por IP (Rate Limiting) para prevenir ataques de fuerza bruta
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100 // Límite de 100 solicitudes por IP cada 15 minutos
});
app.use(limiter);

// Configuración de Winston para el manejo de logs
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/combined.log' }), // Guardar logs en un archivo
    new winston.transports.Console() // Mostrar logs en la consola
  ]
});

// Usar Morgan para generar logs de las solicitudes HTTP
app.use(morgan('combined', { stream: { write: message => logger.info(message) }}));

// Configuración de puerto y URI de MongoDB
const PORT = process.env.PORT || 4000;
const uri = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'secretKey';  // Clave secreta para JWT

// Configuración de cliente de MongoDB para conectar a la base de datos
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let db; // Variable para almacenar la conexión a la base de datos

let usersCollection; // Definir usersCollection como una variable global

async function connectToDatabase() {
  if (db) return db; // Si ya hay una conexión, devolverla
  try {
    await client.connect(); // Conectar a MongoDB
    console.log("Conexión exitosa a MongoDB");
    db = client.db('chefencasa'); // Seleccionar la base de datos 'chefencasa'
    return db;
  } catch (error) {
    console.error('Error al conectar a MongoDB:', error);
    throw error; // Lanzar el error si no se puede conectar
  }
}

// Configuración de Swagger para la documentación de la API
const swaggerOptions = {
  swaggerDefinition: {
    info: {
      title: "Chef en Casa API",
      description: "Documentación de la API",
      version: "1.0.0"
    },
    servers: [
      { url: "https://chefencasabackend-production.up.railway.app"}] // URL del servidor local
  },
  apis: ["index.js"] // Archivo que contiene las rutas de la API
};
const swaggerDocs = swaggerJsDoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs)); // Servir la documentación de Swagger en /api-docs

// Middleware para autenticar el token JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization']; // Obtener el token desde el encabezado
  const token = authHeader && authHeader.split(' ')[1]; // Extraer el token después de 'Bearer'
  if (!token) return res.status(403).json({ message: 'Token requerido' });

  jwt.verify(token, JWT_SECRET, (err, user) => { // Verificar el token con la clave secreta
    if (err) return res.status(403).json({ message: 'Token inválido o expirado' });
    req.user = user; // Añadir los datos del usuario al objeto request
    next(); // Continuar con la siguiente función
  });
}

// Middleware para verificar si el usuario tiene el rol adecuado
function checkRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) { // Comprobar si el rol del usuario es el requerido
      return res.status(403).json({ message: 'Acceso denegado' });
    }
    next(); // Continuar si el rol es correcto
  };
}

// Función para iniciar el servidor y conectar a la base de datos
async function startServer() {
  try {
    const db = await connectToDatabase(); // Conectar a la base de datos
    usersCollection = db.collection('usuarios'); // Asignar la colección a la variable global
    console.log("Conexión exitosa a la base de datos y colección asignada.");

  } catch (error) {
    console.error("Error al conectar a la base de datos:", error);
  }
}

startServer().catch(console.error);

//CARGA DE INGREDIENTES DE LA DB 

let ingredientesMap = {};

async function cargarIngredientesDesdeDB() {
  try {
    const db = await connectToDatabase();
    const ingredientes = await db.collection('ingredientes').find({}).toArray();
    
    ingredientes.forEach(ingrediente => {
      if (ingrediente.nombreOriginal) { // Verificamos que nombreOriginal exista
        ingredientesMap[ingrediente.nombreOriginal.toLowerCase()] = ingrediente.nombreEspanol || ingrediente.nombreOriginal;
      }
    });

    console.log('Ingredientes cargados correctamente desde la base de datos');
  } catch (error) {
    console.error('Error al cargar los ingredientes desde la base de datos:', error);
  }
}

// Llama a la función cuando inicie el servidor
cargarIngredientesDesdeDB();

async function convertirIngredienteAEspanol(ingrediente) {
  try {
    const db = await connectToDatabase();
    const resultado = await db.collection('ingredientes').findOne({ nombreOriginal: ingrediente.toLowerCase() });
    return resultado ? resultado.nombreEspanol : ingrediente;
  } catch (error) {
    console.error('Error al convertir ingrediente al español:', error);
    return ingrediente;
  }
}

async function traducirIngredienteAIngles(ingrediente) {
  try {
    const db = await connectToDatabase();
    const resultado = await db.collection('ingredientes').findOne({ nombreEspanol: ingrediente.toLowerCase() });
    return resultado ? resultado.nombreOriginal : ingrediente;
  } catch (error) {
    console.error('Error al traducir ingrediente a inglés:', error);
    return ingrediente;
  }
}

// Middleware para el manejo centralizado de errores
app.use((err, req, res, next) => {
  console.error(err.stack); // Mostrar el error en la consola
  res.status(500).json({ message: 'Ocurrió un error', error: err.message });
});

//===================================POLITICAS DE PRIVACIDAD=================================================
// Ruta para obtener las políticas de privacidad
app.post('/accept-policies', authenticateToken, async (req, res) => {
  try {
      const result = await usersCollection.updateOne(
          { _id: new ObjectId(req.user.id) },
          { $set: { policiesAccepted: true } }
      );

      if (result.modifiedCount === 0) {
          return res.status(404).json({ message: 'Usuario no encontrado' });
      }

      res.status(200).json({ message: 'Políticas aceptadas correctamente' });
  } catch (error) {
      console.error('Error al aceptar políticas:', error.message);
      res.status(500).json({ message: 'Error al aceptar políticas' });
  }
});


  // Ruta de prueba para verificar que el servidor está funcionando
  app.get('/', (req, res) => {
    res.send('API de Chef en Casa funcionando');
  });

// Ruta de registro de usuarios
// Ruta de registro de usuarios
app.post('/register', async (req, res) => {
  const { nombre, email, password, policiesAccepted, telefono, diet, allergies, role, premium } = req.body;

  // Validar campos obligatorios
  if (!nombre || !email || !password || !telefono || !telefono.prefijo || !telefono.numero) {
    return res.status(400).json({ message: 'Todos los campos son obligatorios, incluyendo el número de teléfono y prefijo' });
  }

  // Validar aceptación de políticas
  if (!policiesAccepted) {
    return res.status(400).json({ message: 'Debe aceptar las políticas de uso para registrarse.' });
  }

  try {
    // Comprobar si el usuario ya existe en la base de datos
    const usuarioExistente = await usersCollection.findOne({ email });
    if (usuarioExistente) {
      return res.status(400).json({ message: 'El usuario ya existe' });
    }

    // Hashear la contraseña antes de guardarla
    const hashedPassword = await bcrypt.hash(password, 10);

    // Crear el nuevo usuario
    const nuevoUsuario = {
  nombre,
  email,
  password: hashedPassword,
  telefono: {
    prefijo: telefono.prefijo,
    numero: telefono.numero,
  },
  diet: diet || null,
  allergies: allergies || [],
  role: role || 'user',
  policiesAccepted: true,
  premium: premium || false, // Si no se especifica, el usuario no es premium por defecto
  healthData: premium
    ? { 
        weight: null, 
        height: null, 
        imc: null, 
        dietRecommendation: null, 
        caloricNeeds: null, 
        tmb: null 
      }
    : null, // HealthData depende de si es premium
};


    // Guardar el nuevo usuario en la base de datos
    await usersCollection.insertOne(nuevoUsuario);

    res.status(201).json({
      message: 'Usuario registrado',
      usuario: {
        nombre: nuevoUsuario.nombre,
        email: nuevoUsuario.email,
        telefono: nuevoUsuario.telefono,
        premium: nuevoUsuario.premium, // Devolver el estado premium en la respuesta
      },
    });
  } catch (error) {
    console.error('Error al registrar usuario:', error.message);
    res.status(500).json({ message: 'Error al registrar usuario', error: error.message });
  }
});



  // Ruta de login de usuarios
  app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) { // Verificar si se envían todos los campos
      return res.status(400).json({ message: 'Todos los campos son obligatorios' });
    }

    // Buscar el usuario en la base de datos
    const usuario = await usersCollection.findOne({ email });
    if (!usuario) {
      return res.status(400).json({ message: 'Email o contraseña incorrectos' });
    }

    // Verificar si la contraseña es válida
    const passwordValido = await bcrypt.compare(password, usuario.password);
    if (!passwordValido) {
      return res.status(400).json({ message: 'Email o contraseña incorrectos' });
    }

    // Generar el token JWT
    /*const token = jwt.sign({ id: usuario._id, email: usuario.email, role: usuario.role }, JWT_SECRET, { expiresIn: '1h' });*/
    const token = jwt.sign(
      { id: usuario._id, email: usuario.email, role: usuario.role },
      JWT_SECRET,
      { expiresIn: '30d' } // Token válido por 30 días
    );

    // Enviar el token de respuesta
    res.status(200).json({ message: 'Login exitoso', token });
  });

  // Ruta protegida para acceder al perfil de usuario solo con token válido
  app.get('/perfil', authenticateToken, async (req, res) => {
  try {
    // Buscar al usuario por su ID en la base de datos
    const usuario = await usersCollection.findOne({ _id: new ObjectId(req.user.id) }, { projection: { password: 0 } });

    if (!usuario) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    // Responder con los datos del usuario (sin la contraseña)
    res.status(200).json(usuario);
  } catch (error) {
    console.error('Error al obtener el perfil del usuario:', error.message);
    res.status(500).json({ message: 'Error al obtener el perfil del usuario', error: error.message });
  }
});

  // Ruta solo accesible para administradores
  app.get('/admin', authenticateToken, checkRole('admin'), (req, res) => {
    res.send('Ruta solo para administradores');
  });

//========================================ACTUALIZAR PERFIL====================================
app.put('/perfil', authenticateToken, async (req, res) => {
  const { nombre, email, password, telefono, diet, allergies } = req.body;

  // Verificar que haya al menos un campo para actualizar
  if (!nombre && !email && !password && !telefono && !diet && !allergies) {
    return res.status(400).json({ message: 'Debe proporcionar al menos un campo para actualizar.' });
  }

  const updates = {};

  // Validar y actualizar el nombre
  if (nombre) updates.nombre = nombre;

  // Validar y actualizar el email
  if (email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: 'El correo electrónico tiene un formato inválido.' });
    }

    const existingUser = await usersCollection.findOne({ email });
    if (existingUser && existingUser._id.toString() !== req.user.id) {
      return res.status(400).json({ message: 'El correo electrónico ya está registrado en otra cuenta.' });
    }

    updates.email = email;
  }

  // Validar y actualizar el teléfono
  if (telefono) {
    const numberRegex = /^\d{9}$/; // Validar que sea un número de 9 dígitos
    if (!numberRegex.test(telefono.numero)) {
      return res.status(400).json({ message: 'El número de teléfono debe tener exactamente 9 dígitos.' });
    }
    updates.telefono = { prefijo: telefono.prefijo || '+0', numero: telefono.numero }; // Usar un prefijo predeterminado si no se envía
  }

  // Actualizar dieta y alergias
  if (diet) updates.diet = diet;
  if (allergies) updates.allergies = allergies;

  // Validar y actualizar la contraseña
  if (password) {
    const passwordRegex = /^(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{6,16}$/;
    if (!passwordRegex.test(password)) {
      return res.status(400).json({
        message: 'La contraseña debe tener entre 6 y 16 caracteres, incluir al menos una mayúscula y un número.',
      });
    }
    updates.password = await bcrypt.hash(password, 10);
  }

  try {
    // Actualizar los campos en la base de datos
    const result = await usersCollection.updateOne(
      { _id: new ObjectId(req.user.id) },
      { $set: updates }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ message: 'No se encontraron cambios en el perfil del usuario.' });
    }

    res.status(200).json({ message: 'Perfil actualizado con éxito.', updates });
  } catch (error) {
    console.error('Error al actualizar el perfil:', error.message);
    res.status(500).json({ message: 'Ocurrió un error al actualizar el perfil. Inténtelo nuevamente más tarde.' });
  }
});



// Configuración para la API de Spoonacular
const SPOONACULAR_API_BASE_URL = 'https://api.spoonacular.com';
const SPOONACULAR_API_KEY = process.env.SPOONACULAR_API_KEY; // Clave API de Spoonacular

const { Translate } = require('@google-cloud/translate').v2; //CLiente de traduccion de google
const translate = new Translate({ key: process.env.GOOGLE_TRANSLATE_API_KEY });

// Función para traducir texto al español
async function translateText(text, targetLanguage = 'es') {
  try {
    let [translation] = await translate.translate(text, targetLanguage);
    return translation;
  } catch (error) {
    console.error('Error al traducir:', error);
    throw error;
  }
}

//===========================================checkRole de usuarios===============================================
// Middleware para verificar el rol del usuario
function checkRole(role) {
  return (req, res, next) => {
    // Verifica si el usuario tiene el rol adecuado
    if (req.user.role !== role) {
      return res.status(403).json({ message: 'Acceso denegado' });
    }
    next(); // Continúa si el rol es correcto
  };
}

//=============================================================IMPORTAR RECETAS ===============================================
// Ruta para importar recetas en lotes desde Spoonacular y almacenarlas en la base de datos
app.post('/importar-recetas', authenticateToken, async (req, res) => {
  try {
    const db = await connectToDatabase();
    const cantidadRecetas = 50; // Cantidad de recetas a obtener por cada solicitud a la API
    let recetasImportadas = 0;
    let offset = 0;

    while (recetasImportadas < 500) { // Puedes ajustar el límite total de recetas
      const params = {
        apiKey: process.env.SPOONACULAR_API_KEY,
        number: cantidadRecetas,
        offset: offset,
      };

      const response = await axios.get(`${SPOONACULAR_API_BASE_URL}/recipes/complexSearch`, { params });
      const recetas = response.data.results;

      if (!recetas || recetas.length === 0) {
        break;
      }

      for (const receta of recetas) {
        const recetaCompleta = await obtenerRecetaDeSpoonacular(receta.id);
        const recetaTraducida = {
          recipeId: recetaCompleta.id,
          title: await translateText(recetaCompleta.title, 'es'),
          image: recetaCompleta.image,
          ingredients: await Promise.all(recetaCompleta.extendedIngredients.map(async (ingrediente) => ({
            name: await translateText(ingrediente.name, 'es'),
            amount: ingrediente.amount,
            unit: ingrediente.unit,
          }))),
          instructions: recetaCompleta.instructions ? await translateText(recetaCompleta.instructions, 'es') : 'No disponible',
          readyInMinutes: recetaCompleta.readyInMinutes,
          servings: recetaCompleta.servings,
          type: recetaCompleta.dishTypes ? recetaCompleta.dishTypes.join(', ') : 'No especificado',
          dateAdded: new Date()
        };

        // Guardar en la base de datos si no existe
        await db.collection('recetas').updateOne(
          { recipeId: recetaCompleta.id },
          { $set: recetaTraducida },
          { upsert: true }
        );
        recetasImportadas++;
      }

      offset += cantidadRecetas;
      console.log(`Importadas ${recetasImportadas} recetas hasta ahora...`);
    }

    res.status(200).json({ message: 'Recetas importadas y almacenadas en la base de datos', total: recetasImportadas });
  } catch (error) {
    console.error('Error al importar recetas:', error.message);
    res.status(500).json({ error: 'Error al importar recetas' });
  }
});

// Función auxiliar para obtener detalles de la receta desde Spoonacular
async function obtenerRecetaDeSpoonacular(recipeId) {
  try {
    const response = await axios.get(`https://api.spoonacular.com/recipes/${recipeId}/information`, {
      params: {
        apiKey: process.env.SPOONACULAR_API_KEY
      }
    });
    return response.data;
  } catch (error) {
    throw new Error('Error al obtener la receta de Spoonacular: ' + error.message);
  }
}

//=======================================================IMPORTAR RECETAS PREMIUM
//=============================================================IMPORTAR RECETAS PREMIUM ===============================================
app.post('/importar-recetas-premium', authenticateToken, async (req, res) => {
  try {
    const db = await connectToDatabase();
    const cantidadRecetas = 50; // Cantidad de recetas a obtener por cada solicitud a la API
    let recetasImportadas = 0;
    let offset = 0;

    while (recetasImportadas < 500) { // Puedes ajustar el límite total de recetas
      const params = {
        apiKey: process.env.SPOONACULAR_API_KEY,
        number: cantidadRecetas,
        offset: offset,
      };

      // Obtener recetas básicas desde Spoonacular
      const response = await axios.get(`${SPOONACULAR_API_BASE_URL}/recipes/complexSearch`, { params });
      const recetas = response.data.results;

      if (!recetas || recetas.length === 0) {
        break;
      }

      for (const receta of recetas) {
        // Obtener detalles completos de la receta
        const recetaCompleta = await obtenerRecetaDeSpoonacular(receta.id);
        // Obtener información nutricional de la receta
        const datosNutricionales = await axios.get(
          `${SPOONACULAR_API_BASE_URL}/recipes/${receta.id}/nutritionWidget.json`,
          { params: { apiKey: process.env.SPOONACULAR_API_KEY } }
        );

        const recetaTraducida = {
          recipeId: recetaCompleta.id,
          title: await translateText(recetaCompleta.title, 'es'),
          image: recetaCompleta.image,
          ingredients: await Promise.all(recetaCompleta.extendedIngredients.map(async (ingrediente) => ({
            name: await translateText(ingrediente.name, 'es'),
            amount: ingrediente.amount,
            unit: ingrediente.unit,
          }))),
          instructions: recetaCompleta.instructions
            ? await translateText(recetaCompleta.instructions, 'es')
            : 'No disponible',
          readyInMinutes: recetaCompleta.readyInMinutes,
          servings: recetaCompleta.servings,
          type: recetaCompleta.dishTypes ? recetaCompleta.dishTypes.join(', ') : 'No especificado',
          dateAdded: new Date(),
          nutrition: {
            calories: datosNutricionales.data.calories,
            carbs: datosNutricionales.data.carbs,
            fat: datosNutricionales.data.fat,
            protein: datosNutricionales.data.protein,
          },
        };

        // Guardar en la colección recetasPremium
        await db.collection('recetasPremium').updateOne(
          { recipeId: recetaCompleta.id },
          { $set: recetaTraducida },
          { upsert: true }
        );

        recetasImportadas++;
      }

      offset += cantidadRecetas;
      console.log(`Importadas ${recetasImportadas} recetas premium hasta ahora...`);
    }

    res.status(200).json({ message: 'Recetas premium importadas y almacenadas en la base de datos', total: recetasImportadas });
  } catch (error) {
    console.error('Error al importar recetas premium:', error.message);
    res.status(500).json({ error: 'Error al importar recetas premium' });
  }
});


//=============================================================BUSCAR RECETAS====================================================
//Ahora busca todas las recetas sin filtro "ingrediente", apareceran todas las recetas a menos que el usuario filtre
//por ingrediente u otro filtro
app.get('/api/recetas', authenticateToken, async (req, res) => {
  let query = req.query.q || '';
  const time = req.query.time || null;
  const maxServings = req.query.maxServings || null;
  const diet = req.query.diet || null;

  try {
    const db = await connectToDatabase();
    // Búsqueda en la base de datos
    const filter = {
      title: { $regex: new RegExp(query, 'i') },
      ...(time && { readyInMinutes: { $lte: Number(time) } }),
      ...(maxServings && { servings: { $lte: Number(maxServings) } }),
      ...(diet && { type: diet })
    };
    const recetas = await db.collection('recetas').find(filter).limit(10).toArray();
    
    res.json({ results: recetas });
  } catch (error) {
    console.error('Error al buscar recetas en la base de datos:', error.message);
    res.status(500).json({ error: 'Error al buscar recetas' });
  }
});

//=============================================================BUSCAR RECETAS PREMIUM====================================================
app.get('/api/recetasPremium', authenticateToken, async (req, res) => {
  const query = req.query.q || ''; // Búsqueda por palabra clave
  const time = req.query.time || null; // Tiempo máximo de preparación
  const maxServings = req.query.maxServings || null; // Máximo de porciones
  const diet = req.query.diet || null; // Tipo de dieta
  const maxCalories = req.query.maxCalories || null; // Máximas calorías

  try {
    const db = await connectToDatabase();
    const usuarioId = new ObjectId(req.user.id); // ID del usuario autenticado

    // Obtener el perfil del usuario para verificar si es premium y obtener sus intolerancias
    const user = await db.collection('usuarios').findOne({ _id: usuarioId });
    if (!user || !user.premium) {
      return res.status(403).json({ error: 'Acceso denegado. Solo disponible para usuarios premium.' });
    }

    // Construir los filtros dinámicamente
    const filter = {
      title: { $regex: new RegExp(query, 'i') }, // Filtro por palabra clave
      ...(time && { readyInMinutes: { $lte: Number(time) } }), // Filtro por tiempo máximo
      ...(maxServings && { servings: { $lte: Number(maxServings) } }), // Filtro por máximo de porciones
      ...(diet && { type: diet }), // Filtro por tipo de dieta
      ...(maxCalories && {
        $expr: {
          $lte: [{ $toInt: '$nutrition.calories' }, Number(maxCalories)]
        }
      }), // Filtro por calorías
    };

    // Agregar el filtro de intolerancias del usuario
    if (user.allergies && user.allergies.length > 0) {
      filter.ingredients = { $not: { $elemMatch: { intolerance: { $in: user.allergies.map(a => a.english) } } } };
    }

    // Buscar en la colección recetasPremium
    const recetas = await db.collection('recetasPremium').find(filter).limit(10).toArray();

    res.json({ results: recetas });
  } catch (error) {
    console.error('Error al buscar recetas premium en la base de datos:', error.message);
    res.status(500).json({ error: 'Error al buscar recetas premium' });
  }
});





//======================================================RECOMENDACIONES======================================================
app.get('/api/recomendaciones', authenticateToken, async (req, res) => {
  try {
    const db = await connectToDatabase();
    const usuarioId = new ObjectId(req.user.id);

    // Obtener ingredientes del almacén del usuario
    const almacen = await db.collection('almacen').findOne({ usuarioId });

    if (!almacen || !almacen.ingredientes || almacen.ingredientes.length === 0) {
      return res.status(200).json({ message: 'No hay ingredientes en el almacén', recomendaciones: [] });
    }

    // Consultar la base de datos de recetas y filtrar según los ingredientes
    const recomendaciones = await db.collection('recetas').find().toArray();

    // Filtrar recetas basadas en coincidencia de ingredientes y cantidades
    const recetasRecomendadas = recomendaciones.map((receta) => {
      if (!receta.ingredients || !Array.isArray(receta.ingredients)) {
        console.error(`Receta inválida: ${receta.title || 'Sin título'} - Campo 'ingredients' faltante o no es un array.`);
        return null; // Saltar recetas inválidas
      }

      const faltantes = [];
      let ingredientesCoinciden = 0;
      let cantidadesSuficientes = 0;

      receta.ingredients.forEach((ingrediente) => {
        const cantidadRecetaEnGramos = convertirMedida(ingrediente.amount, ingrediente.unit);

        if (!cantidadRecetaEnGramos || isNaN(cantidadRecetaEnGramos)) {
          console.error(`Error al convertir la cantidad de ${ingrediente.name}`);
          return;
        }

        // Buscar el ingrediente en el almacén del usuario
        const ingredienteEnAlmacen = almacen.ingredientes.find(i => i.nombre === ingrediente.name);

        if (ingredienteEnAlmacen) {
          // Si el ingrediente está en el almacén, incrementar las coincidencias
          ingredientesCoinciden++;

          // Convertir la cantidad del ingrediente en el almacén a gramos
          const cantidadAlmacenEnGramos = convertirMedida(ingredienteEnAlmacen.cantidad, ingredienteEnAlmacen.unit);

          if (!cantidadAlmacenEnGramos || isNaN(cantidadAlmacenEnGramos)) {
            console.error(`Error al convertir la cantidad de ${ingredienteEnAlmacen.nombre}`);
            return;
          }

          // Verificar si la cantidad en el almacén es suficiente
          if (cantidadAlmacenEnGramos >= cantidadRecetaEnGramos) {
            cantidadesSuficientes++;
          } else {
            // Si la cantidad en el almacén es menor, agregar a faltantes
            faltantes.push({
              nombre: ingrediente.name,
              faltante: cantidadRecetaEnGramos - cantidadAlmacenEnGramos,
            });
          }
        } else {
          // Si el ingrediente no está en el almacén, agregarlo directamente a faltantes
          faltantes.push({ nombre: ingrediente.name, faltante: cantidadRecetaEnGramos });
        }
      });

      // Calcular porcentajes de coincidencia
      const porcentajeCoincidenciaIngredientes = (ingredientesCoinciden / receta.ingredients.length) * 100;
      const porcentajeCoincidenciaCantidad = (cantidadesSuficientes / receta.ingredients.length) * 100;

      // Calcular el porcentaje de coincidencia combinado
      const porcentajeCoincidencia = (porcentajeCoincidenciaIngredientes + porcentajeCoincidenciaCantidad) / 2;

      // Considerar receta recomendada si cumple con al menos el 70% en el porcentaje combinado
      if (porcentajeCoincidencia >= 70) {
        return { 
          ...receta, 
          faltantes,
          porcentajeCoincidencia
        };
      }
      
      return null;
    }).filter(Boolean); // Filtrar recetas que no cumplen con el 70%

    // Debug para verificar ingredientes faltantes
    console.log("Ingredientes faltantes para cada receta recomendada:", recetasRecomendadas.map(r => ({ 
      titulo: r.title, 
      faltantes: r.faltantes 
    })));

    res.json({ recomendaciones: recetasRecomendadas });
  } catch (error) {
    console.error('Error al obtener recomendaciones:', error);
    res.status(500).json({ error: 'Error al obtener recomendaciones' });
  }
});



/*
// Función de conversión de cantidades a gramos (asegúrate de tener el mapa de conversiones configurado correctamente)
function convertirMedida(cantidad, unidad) {
  if (!unidad || unidad.trim() === '') {
    console.warn(`Unidad vacía para la cantidad ${cantidad}, asignando unidad por defecto.`);
    unidad = 'gram';
  }

  if (unidad.endsWith('s')) {
    unidad = unidad.slice(0, -1);
  }

  const conversionFactor = conversiones[unidad.toLowerCase()];
  if (!conversionFactor) {
    console.error(`Unidad desconocida: ${unidad}`);
    return null;
  }

  return cantidad * conversionFactor;
}
*/
/*
// Función auxiliar para obtener y traducir ingredientes de la receta desde Spoonacular
async function obtenerIngredientesReceta(recipeId) {
  try {
    const response = await axios.get(`https://api.spoonacular.com/recipes/${recipeId}/information`, {
      params: {
        apiKey: process.env.SPOONACULAR_API_KEY
      }
    });

    const db = await connectToDatabase();
    
    // Mapear y traducir cada ingrediente
    const ingredientesReceta = await Promise.all(response.data.extendedIngredients.map(async (ingrediente) => {
      const ingredienteBD = await db.collection('ingredientes').findOne({ nombreOriginal: ingrediente.name });

      const nombreTraducido = ingredienteBD ? ingredienteBD.nombreEspanol : ingrediente.name;
      
      console.log(`Ingrediente original: ${ingrediente.name}, Traducido: ${nombreTraducido}`); // Verifica la traducción

      return {
        name: nombreTraducido, // Usa el nombre en español si existe en la BD, si no, usa el nombre original
        amount: ingrediente.amount,
      };
    }));

    return ingredientesReceta;
  } catch (error) {
    throw new Error('Error al obtener y traducir ingredientes de Spoonacular: ' + error.message);
  }
}
*/


//======================================================RECETAS DESAYUNO FILTRADAS==============================
app.get('/api/recetas-breakfast', authenticateToken, async (req, res) => {
  try {
    const db = await connectToDatabase();

    // Filtro para recetas con el tipo "breakfast"
    const filter = {
      type: /breakfast/i, // El campo "type" debe contener "breakfast" (sin importar si tiene otros valores)
    };

    // Consulta a la base de datos para obtener las recetas filtradas
    const recetas = await db.collection('recetas').find(filter).toArray();

    res.json({ results: recetas });
  } catch (error) {
    console.error('Error al buscar recetas de desayuno:', error.message);
    res.status(500).json({ error: 'Error al buscar recetas de desayuno' });
  }
});

//======================================================RECETAS CENA FILTRADAS==============================
app.get('/api/recetas-dinner', authenticateToken, async (req, res) => {
  try {
    const db = await connectToDatabase();

    // Filtro para recetas con el tipo "dinner"
    const filter = {
      type: /dinner/i, // El campo "type" debe contener "dinner" (sin importar si tiene otros valores)
    };

    // Consulta a la base de datos para obtener las recetas filtradas
    const recetas = await db.collection('recetas').find(filter).toArray();

    res.json({ results: recetas });
  } catch (error) {
    console.error('Error al buscar recetas de cena:', error.message);
    res.status(500).json({ error: 'Error al buscar recetas de cena' });
  }
});

//======================================================RECETAS ALMUERZO FILTRADAS==============================
app.get('/api/recetas-lunch', authenticateToken, async (req, res) => {
  try {
    const db = await connectToDatabase();

    // Filtro para recetas con el tipo "lunch"
    const filter = {
      type: /lunch/i, // El campo "type" debe contener "lunch" (sin importar si tiene otros valores)
    };

    // Consulta a la base de datos para obtener las recetas filtradas
    const recetas = await db.collection('recetas').find(filter).toArray();

    res.json({ results: recetas });
  } catch (error) {
    console.error('Error al buscar recetas de almuerzo:', error.message);
    res.status(500).json({ error: 'Error al buscar recetas de almuerzo' });
  }
});

//======================================================RECETAS POSTRES FILTRADAS==============================
app.get('/api/recetas-dessert', authenticateToken, async (req, res) => {
  try {
    const db = await connectToDatabase();

    // Filtro para recetas con el tipo "snack"
    const filter = {
      type: /snack/i, // El campo "type" debe contener "dessert" (sin importar si tiene otros valores)
    };

    // Consulta a la base de datos para obtener las recetas filtradas
    const recetas = await db.collection('recetas').find(filter).toArray();

    res.json({ results: recetas });
  } catch (error) {
    console.error('Error al buscar recetas de postres:', error.message);
    res.status(500).json({ error: 'Error al buscar recetas de postres' });
  }
});



//========================================================INICIAR SERVIDOR========================================
// Iniciar el servidor en el puerto 4000
app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});


module.exports = app;

//chefencasa1@chefencasa-437717.iam.gserviceaccount.com
//GOOGLE_APPLICATION_CREDENTIALS=./ruta/al/archivo_de_credenciales.json

// Probar la función de traducción
async function testTranslation() {
  const text = 'The translation is working';
  try {
    const [translation] = await translate.translate(text, 'es');
    console.log('Traducción:', translation);
  } catch (error) {
    console.error('Error en la traducción:', error);
  }
}

testTranslation();
// Obtener detalles de una receta desde Spoonacular

//============================================INFO RECETA=============================================

app.get('/receta/:id', authenticateToken, async (req, res) => {
  const recipeId = parseInt(req.params.id, 10);

  try {
    const db = await connectToDatabase();
    const receta = await db.collection('recetas').findOne({ recipeId });
    
    if (!receta) {
      return res.status(404).json({ message: 'Receta no encontrada en la base de datos' });
    }

    // Convertir las cantidades de los ingredientes
    const ingredientesConvertidos = receta.ingredients.map((ingrediente) => {
      const cantidadConvertida = convertirMedida(ingrediente.amount, ingrediente.unit, ingrediente.name);
      return {
        ...ingrediente,
        amount: cantidadConvertida,
        unit: 'gram'  // O la unidad en la que desees mostrarlo, como gramos
      };
    });

    res.json({
      ...receta,
      ingredients: ingredientesConvertidos,
    });
  } catch (error) {
    console.error('Error al obtener detalles de la receta:', error.message);
    res.status(500).json({ message: 'Error al obtener detalles de la receta' });
  }
});

//============================================INFO RECETA PREMIUM=============================================

app.get('/recetaPremium/:id', authenticateToken, async (req, res) => {
  const recipeId = req.params.id;

  try {
    const db = await connectToDatabase();
    
    // Verificar si el usuario es premium
    const usuario = await db.collection('usuarios').findOne({ _id: new ObjectId(req.user.id) });
    if (!usuario || !usuario.premium) {
      return res.status(403).json({ message: 'Acceso denegado. Solo disponible para usuarios premium.' });
    }

    // Si el recipeId no es un ObjectId válido, intenta buscarlo como un número en otro campo
    let filter;
    if (ObjectId.isValid(recipeId)) {
      filter = { _id: new ObjectId(recipeId) };
    } else {
      filter = { recipeId: parseInt(recipeId, 10) }; // Busca por un campo alternativo
    }

    // Buscar la receta en la colección `recetasPremium`
    const receta = await db.collection('recetasPremium').findOne(filter);

    if (!receta) {
      return res.status(404).json({ message: 'Receta premium no encontrada en la base de datos' });
    }

    // Convertir las cantidades de los ingredientes
    const ingredientesConvertidos = receta.ingredients.map((ingrediente) => {
      const cantidadConvertida = convertirMedida(ingrediente.amount, ingrediente.unit, ingrediente.name);
      return {
        ...ingrediente,
        amount: cantidadConvertida,
        unit: 'gram', // Convertir las unidades a gramos o a la unidad estándar deseada
      };
    });

    res.json({
      ...receta,
      ingredients: ingredientesConvertidos,
      nutrition: receta.nutrition, // Incluir la información nutricional
    });
  } catch (error) {
    console.error('Error al obtener detalles de la receta premium:', error.message);
    res.status(500).json({ message: 'Error al obtener detalles de la receta premium' });
  }
});




/*
// Función para obtener detalles de la receta desde Spoonacular
async function obtenerRecetaDeSpoonacular(recipeId) {
  try {
    const response = await axios.get(`https://api.spoonacular.com/recipes/${recipeId}/information`, {
      params: {
        apiKey: process.env.SPOONACULAR_API_KEY
      }
    });

    return response.data;
  } catch (error) {
    throw new Error('Error al obtener la receta de Spoonacular: ' + error.message);
  }
}
*/
/*
//===================================================RECLAMOS=================================================
// Ruta para enviar un reclamo (usuario)
app.post('/reclamos', authenticateToken, async (req, res) => {
  const { nombre, email, titulo, destinatario, comentario } = req.body;

  if (!nombre || !email || !titulo || !destinatario || !comentario) {
    return res.status(400).json({ message: 'Todos los campos son obligatorios' });
  }

  try {
    await client.connect();
    const db = client.db('chefencasa');
    const reclamosCollection = db.collection('reclamos');

    const nuevoReclamo = {
      usuarioId: req.user.id, //ID del usuario autenticado
      nombre,
      email,
      titulo,
      destinatario,
      comentario,
      estado: 'En espera', 
      fechaCreacion: new Date()
    };

    await reclamosCollection.insertOne(nuevoReclamo);
    res.status(201).json({ message: 'Reclamo enviado con éxito' });
  } catch (error) {
    res.status(500).json({ message: 'Error al enviar el reclamo', error: error.message });
  } finally {
    await client.close();
  }
});
*/


//===================================================INGREDIENTES=============================================


// Ruta para obtener ingredientes desde la base de datos
app.get('/ingredientes', authenticateToken, async (req, res) => {
  try {
    const db = await connectToDatabase();
    const ingredientes = await db.collection('ingredientes').find().toArray();

    res.status(200).json({ results: ingredientes }); // Asegúrate de enviar siempre un estado 200
  } catch (error) {
    console.error('Error al obtener ingredientes:', error.message);
    res.status(500).json({ error: 'Error al obtener ingredientes' });
  }
});

// Ruta para importar todos los ingredientes desde Spoonacular y guardarlos en la base de datos
app.post('/importar-todos-los-ingredientes', authenticateToken, async (req, res) => {
  try {
    const db = await connectToDatabase();
    const letras = 'abcdefghijklmnopqrstuvwxyz'.split(''); // Array de letras para las consultas
    const number = 100; // Número de ingredientes por solicitud (máximo permitido por Spoonacular)
    let ingredientesImportados = 0;

    // Iterar sobre cada letra del abecedario para hacer solicitudes
    for (const letra of letras) {
      let offset = 0; // Iniciar desde el primer ingrediente con cada letra
      let totalResultados = 0;

      do {
        // Hacer la solicitud a Spoonacular para obtener los ingredientes paginados
        const response = await axios.get('https://api.spoonacular.com/food/ingredients/search', {
          params: {
            apiKey: SPOONACULAR_API_KEY,
            query: letra, // Usar la letra actual como parámetro de búsqueda
            offset, // Desplazamiento de la búsqueda
            number // Número de ingredientes por solicitud
          }
        });

        // Obtener los ingredientes desde la respuesta
        const ingredientes = response.data.results;
        totalResultados = response.data.totalResults; // Número total de ingredientes en Spoonacular

        // Guardar los ingredientes en la base de datos con su traducción
        for (const ingrediente of ingredientes) {
          // Traducir el nombre del ingrediente usando la función translateText
          const nombreTraducido = await translateText(ingrediente.name.toLowerCase(), 'es');

          // Guardar o actualizar el ingrediente en la base de datos
          await db.collection('ingredientes').updateOne(
            { nombreOriginal: ingrediente.name.toLowerCase() }, // Buscar por nombre original
            {
              $set: {
                nombreOriginal: ingrediente.name.toLowerCase(),
                nombreEspanol: nombreTraducido,
                image: ingrediente.image,
              }
            },
            { upsert: true } // Si no existe, crear un nuevo registro
          );
        }

        // Incrementar el contador de ingredientes importados y el offset
        ingredientesImportados += ingredientes.length;
        offset += number;

        console.log(`Importados ${ingredientesImportados} ingredientes usando la letra '${letra}'...`);
      } while (offset < totalResultados); // Continuar hasta que se hayan importado todos los ingredientes con la letra actual
    }

    res.status(200).json({ message: 'Todos los ingredientes importados y almacenados en la base de datos' });
  } catch (error) {
    console.error('Error al importar todos los ingredientes:', error.response ? error.response.data : error.message);
    res.status(500).json({ error: 'Error al importar todos los ingredientes' });
  }
});

//============================================MEDIDAS NORMALIZACION===============================
//================================================================================================

// Mapa de conversiones para normalizar unidades a gramos
const conversiones = {
  'gram': 1,          
  'ml': 1,            
  'kg': 1000,         
  'l': 1000,          
  'tbsp': 15,         
  'tsp': 5,           
  'cup': 240,         
  'oz': 25,           
  'lb': 450,          
  'pinche': 0.36,     
  'clove': 5,         
  'head': 1000,       
  'ounce': 25,        
  'serving': 0.5,     
  'strip': 5,         
  'large': 100,       
  'unidad': 100,      
  'c': 240,           
  't': 50,            
  'small': 100,       
  'tablespoon': 15,   
  'teaspoon': 5,      
  'can': 300,         
  'slice': 5,         
  'pinch': 0.5,       
  'container': 500,   
  'dash': 0.5,        
  'bunch': 100,       
  'bottle': 250,      
  'jar': 200,         
  'bowl': 300,        
  'pint': 470,        
  'quart': 946,       
  'gallon': 3785,     
  'Tb': 15,           
  'handful': 50,      
  'medium size': 100, 
  'medium': 100,      
  'large size': 200,  
  'leaf': 10,
  'large handful': 75,
  'piece': 50,
  'large can': 600,
  'bag': 100,         
  'box': 100,         
  'stalk': 100,       
  'stick': 50,        
  'dash': 0.5,        
  '8-inch': 100,      
  'inch': 15,         
  'small head': 100,  
  'large head': 200,  
  'medium head': 150, 
  'fillet': 200,      
  // añadir otras unidades según sea necesario
};

const unidadesDesconocidas = new Set();

function convertirMedida(cantidad, unidad, nombreIngrediente) {
  // Comprobar si cantidad o unidad son undefined
  if (cantidad === undefined || unidad === undefined) {
    console.warn(`Datos faltantes para ${nombreIngrediente || 'ingrediente desconocido'}: cantidad=${cantidad}, unidad=${unidad}`);
    return cantidad || 0;  // Retornar cantidad como está o 0 si es undefined
  }

  if (!unidad || unidad.trim() === '') {
    console.warn(`Unidad vacía para ${nombreIngrediente || 'ingrediente desconocido'} con cantidad ${cantidad}. Asignando unidad por defecto.`);
    unidad = ['agua', 'caldo', 'jugo'].includes((nombreIngrediente || '').toLowerCase()) ? 'ml' : 'gram';
  }

  // Normalizar la unidad a minúsculas y singular si es plural
  unidad = unidad.toLowerCase().endsWith('s') ? unidad.slice(0, -1) : unidad.toLowerCase();

  const conversionFactor = conversiones[unidad];

  if (!conversionFactor) {
    console.warn(`Unidad desconocida: ${unidad} para ${nombreIngrediente || 'ingrediente desconocido'}. Utilizando cantidad sin conversión.`);
    unidadesDesconocidas.add(unidad);
    return cantidad;
  }

  return cantidad * conversionFactor;
}

// Mostrar las unidades desconocidas al salir
process.on('exit', () => {
  if (unidadesDesconocidas.size > 0) {
    console.log("Unidades desconocidas encontradas:", Array.from(unidadesDesconocidas));
  }
});


//============================================ALMACEN=============================================
//================================================================================================
// Revisar almacén
app.get('/almacen', authenticateToken, async (req, res) => {
  try {
    const db = await connectToDatabase();
    const almacen = await db.collection('almacen').findOne({ usuarioId: new ObjectId(req.user.id) });

    // Si el almacén no existe o no contiene ingredientes
    if (!almacen || !almacen.ingredientes || almacen.ingredientes.length === 0) {
      return res.status(200).json({ message: 'No hay ingredientes en el almacén', ingredientes: [] });
    }

    // Actualizar los ingredientes para incluir el nombre en español
    const ingredientesActualizados = await Promise.all(
      almacen.ingredientes.map(async (ingrediente) => {
        const ingredienteDb = await db.collection('ingredientes').findOne({ nombreOriginal: ingrediente.nombre });

        return {
          ...ingrediente,
          nombreEspanol: ingredienteDb ? ingredienteDb.nombreEspanol : ingrediente.nombre, // Usar el nombre en español si está disponible
          img: ingrediente.img || ingredienteDb?.image || '' // Usar imagen si está disponible en la base de datos
        };
      })
    );

    res.status(200).json({ ...almacen, ingredientes: ingredientesActualizados });
  } catch (error) {
    console.error('Error al obtener el almacén:', error.message);
    res.status(500).json({ error: 'Error al obtener el almacén' });
  }
});

// Ruta para agregar ingredientes al almacén
app.post('/almacen/registro', authenticateToken, async (req, res) => {
  const { ingredientes } = req.body;

  try {
    const db = await connectToDatabase();

    const ingredientesParaRegistrar = await Promise.all(
      ingredientes.map(async (ing) => {
        const nombreParaBuscar = ing.nombreOriginal || ing.nombre || ing.nombreEspanol;
        if (!nombreParaBuscar) {
          throw new Error(`El ingrediente no tiene nombre válido: ${JSON.stringify(ing)}`);
        }

        const ingredienteDb = await db.collection('ingredientes').findOne({
          $or: [
            { nombreOriginal: nombreParaBuscar.toLowerCase() },
            { nombreEspanol: nombreParaBuscar.toLowerCase() }
          ]
        });

        if (!ingredienteDb) {
          throw new Error(`El ingrediente ${nombreParaBuscar} no existe en la base de datos de ingredientes`);
        }

        // Aquí se asegura de que la imagen esté presente en el objeto que se guardará en el almacén
        return {
          nombre: nombreParaBuscar.toLowerCase(),
          nombreEspanol: ingredienteDb.nombreEspanol || ing.nombreEspanol,
          cantidad: ing.cantidad,
          img: ing.image || ingredienteDb.image, // Verificar que la imagen existe en 'ing' o 'ingredienteDb'
          fechaIngreso: new Date(),
          perecedero: ing.perecedero || false
        };
      })
    );

    await crearOActualizarAlmacen(db, req.user.id, ingredientesParaRegistrar);
    res.status(200).json({ message: 'Alimentos registrados o actualizados en el almacén' });
  } catch (error) {
    console.error('Error al registrar alimentos:', error);
    res.status(500).json({ error: 'Error al registrar alimentos' });
  }
});

// Eliminar un ingrediente completo del almacén
app.delete('/almacen/eliminar', authenticateToken, async (req, res) => {
  const { nombreIngrediente } = req.body; // El nombre del ingrediente que se quiere eliminar

  if (!nombreIngrediente) {
    return res.status(400).json({ message: 'Debe proporcionar el nombre del ingrediente' });
  }

  try {
    const db = await connectToDatabase();
    const usuarioId = new ObjectId(req.user.id);

    // Buscar y eliminar el ingrediente del almacén del usuario
    const result = await db.collection('almacen').updateOne(
      { usuarioId },
      { $pull: { ingredientes: { nombre: nombreIngrediente.toLowerCase() } } }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ message: 'Ingrediente no encontrado en el almacén' });
    }

    res.status(200).json({ message: `Ingrediente ${nombreIngrediente} eliminado correctamente` });
  } catch (error) {
    console.error('Error al eliminar el ingrediente:', error.message);
    res.status(500).json({ error: 'Error al eliminar el ingrediente del almacén' });
  }
});

// Reducir la cantidad de un ingrediente en el almacén
app.put('/almacen/reducir', authenticateToken, async (req, res) => {
  const { nombreIngrediente, cantidadReducir } = req.body;

  try {
    const db = await connectToDatabase();
    const usuarioId = new ObjectId(req.user.id);

    // Buscar el ingrediente en la colección de ingredientes importados
    const ingredienteDb = await db.collection('ingredientes').findOne({ nombreOriginal: nombreIngrediente.toLowerCase() });
    if (!ingredienteDb) {
      return res.status(400).json({ message: `El ingrediente ${nombreIngrediente} no existe en la base de datos` });
    }

    // Continuar con la lógica para reducir la cantidad en el almacén del usuario
    const almacen = await db.collection('almacen').findOne({ usuarioId });
    if (!almacen) {
      return res.status(404).json({ message: 'Almacén no encontrado' });
    }

    const ingredienteEnAlmacen = almacen.ingredientes.find(item => item.nombre === nombreIngrediente.toLowerCase());

    if (!ingredienteEnAlmacen || ingredienteEnAlmacen.cantidad < cantidadReducir) {
      return res.status(400).json({ message: 'No hay suficiente cantidad para reducir' });
    }

    // Reducir la cantidad
    ingredienteEnAlmacen.cantidad -= cantidadReducir;
    if (ingredienteEnAlmacen.cantidad <= 0) {
      // Eliminar el ingrediente si la cantidad llega a 0
      await db.collection('almacen').updateOne(
        { usuarioId },
        { $pull: { ingredientes: { nombre: nombreIngrediente.toLowerCase() } } }
      );
    } else {
      // Actualizar la cantidad
      await db.collection('almacen').updateOne(
        { usuarioId, 'ingredientes.nombre': nombreIngrediente.toLowerCase() },
        { $set: { 'ingredientes.$.cantidad': ingredienteEnAlmacen.cantidad } }
      );
    }

    res.status(200).json({ message: 'Cantidad reducida correctamente' });
  } catch (error) {
    console.error('Error al reducir la cantidad:', error.message);
    res.status(500).json({ error: 'Error al reducir la cantidad' });
  }
});

// Aumentar la cantidad de un ingrediente en el almacén
app.put('/almacen/aumentar', authenticateToken, async (req, res) => {
  const { nombreIngrediente, cantidadAumentar } = req.body; // El nombre del ingrediente y la cantidad a aumentar

  if (!nombreIngrediente || !cantidadAumentar) {
    return res.status(400).json({ message: 'Debe proporcionar el nombre del ingrediente y la cantidad a aumentar' });
  }

  try {
    const db = await connectToDatabase();
    const usuarioId = new ObjectId(req.user.id);

    // Buscar el ingrediente en el almacén del usuario
    const almacen = await db.collection('almacen').findOne({ usuarioId });
    if (!almacen) {
      return res.status(404).json({ message: 'Almacén no encontrado' });
    }

    // Buscar el ingrediente en el almacén del usuario
    const ingrediente = almacen.ingredientes.find(item => item.nombre === nombreIngrediente.toLowerCase());

    if (!ingrediente) {
      return res.status(404).json({ message: `Ingrediente ${nombreIngrediente} no encontrado en el almacén` });
    }

    // Aumentar la cantidad del ingrediente
    ingrediente.cantidad += cantidadAumentar;

    // Actualizar la cantidad del ingrediente en el almacén
    await db.collection('almacen').updateOne(
      { usuarioId, 'ingredientes.nombre': nombreIngrediente.toLowerCase() },
      { $set: { 'ingredientes.$.cantidad': ingrediente.cantidad } }
    );

    res.status(200).json({ message: `Cantidad de ${nombreIngrediente} aumentada correctamente` });
  } catch (error) {
    console.error('Error al aumentar la cantidad del ingrediente:', error.message);
    res.status(500).json({ error: 'Error al aumentar la cantidad del ingrediente' });
  }
});

// Modificar la cantidad de un ingrediente en el almacén
app.put('/almacen/modificar', authenticateToken, async (req, res) => {
  const { nombreIngrediente, nuevaCantidad } = req.body; // El nombre del ingrediente y la nueva cantidad

  if (!nombreIngrediente || nuevaCantidad === undefined || nuevaCantidad < 0) {
    return res.status(400).json({ message: 'Debe proporcionar el nombre del ingrediente y una cantidad válida' });
  }

  try {
    const db = await connectToDatabase();
    const usuarioId = new ObjectId(req.user.id);

    // Buscar el almacén del usuario
    const almacen = await db.collection('almacen').findOne({ usuarioId });
    if (!almacen) {
      return res.status(404).json({ message: 'Almacén no encontrado' });
    }

    // Verificar si el ingrediente existe en el almacén
    const ingrediente = almacen.ingredientes.find(item => item.nombre === nombreIngrediente.toLowerCase());
    if (!ingrediente) {
      return res.status(404).json({ message: `Ingrediente ${nombreIngrediente} no encontrado en el almacén` });
    }

    // Actualizar la cantidad del ingrediente
    await db.collection('almacen').updateOne(
      { usuarioId, 'ingredientes.nombre': nombreIngrediente.toLowerCase() },
      { $set: { 'ingredientes.$.cantidad': nuevaCantidad } }
    );

    res.status(200).json({ message: `Cantidad de ${nombreIngrediente} modificada correctamente` });
  } catch (error) {
    console.error('Error al modificar la cantidad del ingrediente:', error.message);
    res.status(500).json({ error: 'Error al modificar la cantidad del ingrediente' });
  }
});


// ============================================ PREPARAR RECETA ====================================
// Descontar ingredientes del almacén al preparar receta desde Spoonacular y generar una única lista de compras
app.post('/descontar-ingredientes', authenticateToken, async (req, res) => {
  const { ingredientesParaDescontar } = req.body;

  try {
    const usuarioId = new ObjectId(req.user.id);
    const db = await connectToDatabase();

    for (const ingrediente of ingredientesParaDescontar) {
      await db.collection('almacen').updateOne(
        { usuarioId, 'ingredientes.nombre': ingrediente.nombre },
        { $inc: { 'ingredientes.$.cantidad': -ingrediente.cantidad } }
      );
    }

    res.status(200).json({ message: 'Ingredientes descontados correctamente.' });
  } catch (error) {
    console.error('Error al descontar ingredientes:', error.message);
    res.status(500).json({ error: 'Error al descontar ingredientes' });
  }
});


/*
// Función mejorada para convertir la cantidad y unidad a gramos o mililitros
function convertirMedida(cantidad, unidad) {
  // Verificar si la unidad es una cadena vacía o nula
  if (!unidad || unidad.trim() === '') {
    console.warn(`Unidad vacía para la cantidad ${cantidad}, asignando unidad por defecto.`);
    unidad = 'gram'; // Asignar una unidad por defecto si está vacía, como 'gram'
  }

  // Convertir la unidad a singular si es plural
  if (unidad.endsWith('s')) {
    unidad = unidad.slice(0, -1); // Quitar la 's' final para convertir a singular
  }

  const conversionFactor = conversiones[unidad.toLowerCase()];
  if (!conversionFactor) {
    console.error(`Unidad desconocida: ${unidad}`);
    return null;
  }

  return cantidad * conversionFactor;
}
*/

//============================================LISTA DE COMPRAS====================================
// Generar lista de compras
app.post('/verificar-ingredientes', authenticateToken, async (req, res) => {
  const { recipeId } = req.body;

  try {
    const db = await connectToDatabase();
    const receta = await db.collection('recetas').findOne({ recipeId });
    if (!receta) {
      return res.status(404).json({ message: 'Receta no encontrada' });
    }

    const usuarioId = new ObjectId(req.user.id);
    const almacen = await db.collection('almacen').findOne({ usuarioId });
    if (!almacen) {
      return res.status(404).json({ message: 'Almacén no encontrado' });
    }

    const faltanIngredientes = [];
    const ingredientesParaDescontar = [];

    for (const ingredienteReceta of receta.ingredients) {
      const cantidadEnGramos = convertirMedida(ingredienteReceta.amount, ingredienteReceta.unit);
      if (!cantidadEnGramos || isNaN(cantidadEnGramos)) {
        return res.status(500).json({ error: `Error al convertir la cantidad de ${ingredienteReceta.name}` });
      }

      const ingredienteEnAlmacen = almacen.ingredientes.find(item => item.nombre === ingredienteReceta.name);

      if (!ingredienteEnAlmacen || ingredienteEnAlmacen.cantidad < cantidadEnGramos) {
        faltanIngredientes.push({
          nombre: ingredienteReceta.name,
          cantidad: cantidadEnGramos,
        });
      } else {
        ingredientesParaDescontar.push({
          nombre: ingredienteReceta.name,
          cantidad: cantidadEnGramos,
        });
      }
    }

    if (faltanIngredientes.length > 0) {
      await db.collection('listasDeCompras').updateOne(
        { usuarioId },
        { $set: { ingredientes: faltanIngredientes, completada: false } },
        { upsert: true }
      );
      return res.status(200).json({
        message: 'No tienes suficientes ingredientes. Se ha generado una lista de compras.',
        compraNecesaria: true,
        faltanIngredientes,
      });
    }

    return res.status(200).json({
      message: 'Tienes todos los ingredientes.',
      compraNecesaria: false,
      ingredientesParaDescontar,
    });
  } catch (error) {
    console.error('Error al verificar ingredientes:', error.message);
    res.status(500).json({ error: 'Error al verificar ingredientes' });
  }
});

// Función para convertir la cantidad y unidad a gramos o mililitros
function convertirMedida(cantidad, unidad) {
  if (!unidad || unidad.trim() === '') {
    console.warn(`Unidad vacía para la cantidad ${cantidad}, asignando unidad por defecto.`);
    unidad = 'gram';
  }

  if (unidad.endsWith('s')) {
    unidad = unidad.slice(0, -1);
  }

  const conversionFactor = conversiones[unidad.toLowerCase()];
  if (!conversionFactor) {
    console.error(`Unidad desconocida: ${unidad}`);
    return null;
  }

  return cantidad * conversionFactor;
}


// VER LISTA DE COMPRAS
app.get('/lista-de-compras', authenticateToken, async (req, res) => {
  try {
    const db = await connectToDatabase();
    const usuarioId = new ObjectId(req.user.id);
    const listaDeCompras = await db.collection('listasDeCompras').findOne({ usuarioId, completada: false });

    if (!listaDeCompras) {
      return res.status(200).json({ message: 'No tienes ningún ingrediente en tu lista de compras', listaVacia: true });
    }

    // Responder con la lista de compras si existe
    res.status(200).json({ ...listaDeCompras, listaVacia: false });
  } catch (error) {
    res.status(500).json({ error: `Error al obtener la lista de compras: ${error.message}` });
  }
});

// Marcar como comprada la lista o eliminarla
app.put('/lista-de-compras/marcar-comprada', authenticateToken, async (req, res) => {
  try {
    const db = await connectToDatabase();
    const usuarioId = new ObjectId(req.user.id);
    
    await db.collection('listasDeCompras').updateOne(
      { usuarioId },
      { $set: { completada: true } }
    );

    res.status(200).json({ message: 'Lista de compras marcada como comprada' });
  } catch (error) {
    res.status(500).json({ error: `Error al marcar la lista de compras como comprada: ${error.message}` });
  }
});

// Eliminar la lista de compras
app.delete('/lista-de-compras/eliminar', authenticateToken, async (req, res) => {
  try {
    const db = await connectToDatabase();
    const usuarioId = new ObjectId(req.user.id);

    await db.collection('listasDeCompras').deleteOne({ usuarioId });

    res.status(200).json({ message: 'Lista de compras eliminada exitosamente' });
  } catch (error) {
    res.status(500).json({ error: `Error al eliminar la lista de compras: ${error.message}` });
  }
});

// Ruta para actualizar la cantidad de un ingrediente en la lista de compras
app.put('/lista-de-compras/actualizar-cantidad', authenticateToken, async (req, res) => {
  const { nombreIngrediente, nuevaCantidad } = req.body;

  if (!nombreIngrediente || !nuevaCantidad || nuevaCantidad <= 0) {
    return res.status(400).json({ message: 'Debe proporcionar un nombre de ingrediente y una cantidad válida mayor que 0' });
  }

  try {
    const db = await connectToDatabase();
    const usuarioId = new ObjectId(req.user.id);

    const result = await db.collection('listasDeCompras').updateOne(
      { usuarioId, 'ingredientes.nombre': nombreIngrediente },
      { $set: { 'ingredientes.$.cantidad': nuevaCantidad } }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ message: 'Ingrediente no encontrado en la lista de compras' });
    }

    res.status(200).json({ message: 'Cantidad del ingrediente actualizada' });
  } catch (error) {
    res.status(500).json({ message: 'Error al actualizar la cantidad del ingrediente', error: error.message });
  }
});

// Ruta para marcar ingredientes como comprados o no comprados
app.put('/lista-de-compras/marcar-comprado', authenticateToken, async (req, res) => {
  const { nombreIngrediente, comprado } = req.body;

  if (!nombreIngrediente || typeof comprado !== 'boolean') {
    return res.status(400).json({ message: 'Debe proporcionar un nombre de ingrediente y un valor booleano para comprado' });
  }

  try {
    const db = await connectToDatabase();
    const usuarioId = new ObjectId(req.user.id);

    const result = await db.collection('listasDeCompras').updateOne(
      { usuarioId, 'ingredientes.nombre': nombreIngrediente },
      { $set: { 'ingredientes.$.comprado': comprado } }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ message: 'Ingrediente no encontrado en la lista de compras' });
    }

    res.status(200).json({ message: 'Estado de compra del ingrediente actualizado' });
  } catch (error) {
    res.status(500).json({ message: 'Error al actualizar el estado de compra del ingrediente', error: error.message });
  }
});

// Ruta para transferir ingredientes comprados al almacén
app.put('/lista-de-compras/transferir-al-almacen', authenticateToken, async (req, res) => {
  try {
    const db = await connectToDatabase();
    const usuarioId = new ObjectId(req.user.id);

    const listaDeCompras = await db.collection('listasDeCompras').findOne({ usuarioId, completada: false });

    if (!listaDeCompras) {
      return res.status(404).json({ message: 'No tienes lista de compras activa' });
    }

    const ingredientesComprados = listaDeCompras.ingredientes.filter(ingrediente => ingrediente.comprado);

    for (const ingrediente of ingredientesComprados) {
      const ingredienteEnAlmacen = await db.collection('almacen').findOne({
        usuarioId,
        'ingredientes.nombre': ingrediente.nombre
      });

      if (ingredienteEnAlmacen) {
        await db.collection('almacen').updateOne(
          { usuarioId, 'ingredientes.nombre': ingrediente.nombre },
          { $inc: { 'ingredientes.$.cantidad': ingrediente.cantidad } }
        );
      } else {
        await db.collection('almacen').updateOne(
          { usuarioId },
          { $push: { ingredientes: { nombre: ingrediente.nombre, cantidad: ingrediente.cantidad, perecedero: true } } }
        );
      }
    }

    await db.collection('listasDeCompras').deleteOne({ usuarioId });
    res.status(200).json({ message: 'Ingredientes transferidos al almacén y lista de compras eliminada' });
  } catch (error) {
    res.status(500).json({ message: 'Error al transferir los ingredientes al almacén', error: error.message });
  }
});

// Ruta para eliminar un ingrediente específico de la lista de compras
app.delete('/lista-de-compras/eliminar-ingrediente', authenticateToken, async (req, res) => {
  const { nombreIngrediente } = req.body;

  if (!nombreIngrediente) {
    return res.status(400).json({ message: 'Debe proporcionar un nombre de ingrediente' });
  }

  try {
    const db = await connectToDatabase();
    const usuarioId = new ObjectId(req.user.id);

    // Eliminar el ingrediente de la lista de compras
    await db.collection('listasDeCompras').updateOne(
      { usuarioId },
      { $pull: { ingredientes: { nombre: nombreIngrediente } } }
    );

    res.status(200).json({ message: 'Ingrediente eliminado de la lista de compras' });
  } catch (error) {
    res.status(500).json({ message: 'Error al eliminar el ingrediente de la lista de compras', error: error.message });
  }
});

// Marcar todos los ingredientes de la lista de compras como comprados
app.put('/lista-de-compras/marcar-todo-comprado', authenticateToken, async (req, res) => {
  try {
    const db = await connectToDatabase();
    const usuarioId = new ObjectId(req.user.id);

    // Buscar la lista de compras del usuario
    const listaDeCompras = await db.collection('listasDeCompras').findOne({ usuarioId, completada: false });

    if (!listaDeCompras) {
      return res.status(404).json({ message: 'No tienes lista de compras activa' });
    }

    // Marcar todos los ingredientes como comprados
    await db.collection('listasDeCompras').updateOne(
      { usuarioId, completada: false },
      { $set: { 'ingredientes.$[].comprado': true } } // Actualizar todos los ingredientes a "comprado: true"
    );

    res.status(200).json({ message: 'Todos los ingredientes marcados como comprados' });
  } catch (error) {
    console.error('Error al marcar todos los ingredientes como comprados:', error.message);
    res.status(500).json({ message: 'Error al marcar los ingredientes como comprados' });
  }
});

// Eliminar toda la lista de compras
app.delete('/lista-de-compras/eliminar-toda', authenticateToken, async (req, res) => {
  try {
    const db = await connectToDatabase();
    const usuarioId = new ObjectId(req.user.id);

    // Eliminar la lista de compras del usuario
    const result = await db.collection('listasDeCompras').deleteOne({ usuarioId });

    if (result.deletedCount === 0) {
      return res.status(404).json({ message: 'No tienes lista de compras para eliminar' });
    }

    res.status(200).json({ message: 'Lista de compras eliminada exitosamente' });
  } catch (error) {
    console.error('Error al eliminar la lista de compras:', error.message);
    res.status(500).json({ message: 'Error al eliminar la lista de compras' });
  }
});

// Ruta para agregar ingredientes específicos a la lista de compras
app.post('/lista-de-compras/agregar', authenticateToken, async (req, res) => {
  const { ingredientes } = req.body;
  const usuarioId = new ObjectId(req.user.id);

  if (!ingredientes || ingredientes.length === 0) {
    return res.status(400).json({ message: 'Debe proporcionar al menos un ingrediente para agregar a la lista de compras' });
  }

  try {
    const db = await connectToDatabase();

    // Verificar si el usuario ya tiene una lista de compras activa
    const listaExistente = await db.collection('listasDeCompras').findOne({ usuarioId, completada: false });

    if (listaExistente) {
      // Actualizar la lista de compras existente con los nuevos ingredientes
      for (const ingrediente of ingredientes) {
        const ingredienteExistente = listaExistente.ingredientes.find(i => i.nombre === ingrediente.nombre);
        
        if (ingredienteExistente) {
          // Si el ingrediente ya existe, incrementa la cantidad faltante
          await db.collection('listasDeCompras').updateOne(
            { usuarioId, 'ingredientes.nombre': ingrediente.nombre },
            { $inc: { 'ingredientes.$.cantidad': ingrediente.faltante } }
          );
        } else {
          // Si el ingrediente no existe en la lista, agrégalo como nuevo
          await db.collection('listasDeCompras').updateOne(
            { usuarioId },
            { $push: { ingredientes: { nombre: ingrediente.nombre, cantidad: ingrediente.faltante, comprado: false } } }
          );
        }
      }
    } else {
      // Crear una nueva lista de compras con los ingredientes proporcionados
      await db.collection('listasDeCompras').insertOne({
        usuarioId,
        ingredientes: ingredientes.map(ingrediente => ({
          nombre: ingrediente.nombre,
          cantidad: ingrediente.faltante,
          comprado: false
        })),
        completada: false
      });
    }

    res.status(200).json({ message: 'Ingredientes agregados a la lista de compras exitosamente' });
  } catch (error) {
    console.error('Error al agregar ingredientes a la lista de compras:', error.message);
    res.status(500).json({ error: 'Error al agregar ingredientes a la lista de compras' });
  }
});





//============================================DESPERDICIO DE ALIMENTOS=============================================
//Funcion para revisar desperdicio de alimentos en almacen
// const cron = require('node-cron');

// // Tarea programada para revisar cada semana los alimentos perecederos
// cron.schedule('0 0 * * 0', async () => {
//   try {
//     const db = await connectToDatabase(); // Conectar a la base de datos
//     const todosLosAlmacenes = await db.collection('almacen').find({}).toArray();
    
//     todosLosAlmacenes.forEach(almacen => {
//       almacen.ingredientes.forEach(ingrediente => {
//         if (ingrediente.perecedero && new Date() - new Date(ingrediente.fechaIngreso) > 7 * 24 * 60 * 60 * 1000) {
//           // Registrar desperdicio si no fue consumido en una semana
//           console.log(`Ingrediente ${ingrediente.nombre} se considera desperdicio`);
//         }
//       });
//     });
//   } catch (error) {
//     console.error('Error al procesar el desperdicio:', error);
//   }
// });

//============================================TESTING DESPERDICIO DE ALIMENTOS=============================================
app.get('/test-desperdicio', async (req, res) => {
  try {
    const db = await connectToDatabase(); // Conectar a la base de datos
    const todosLosAlmacenes = await db.collection('almacen').find({}).toArray();
    
    todosLosAlmacenes.forEach(almacen => {
      almacen.ingredientes.forEach(ingrediente => {
        if (ingrediente.perecedero && new Date() - new Date(ingrediente.fechaIngreso) > 7 * 24 * 60 * 60 * 1000) {
          // Registrar desperdicio si no fue consumido en una semana
          console.log(`Ingrediente ${ingrediente.nombre} se considera desperdicio`);
        }
      });
    });

    res.status(200).json({ message: 'Revisión de desperdicio completada' });
  } catch (error) {
    console.error('Error al procesar el desperdicio:', error);
    res.status(500).json({ error: 'Error al procesar el desperdicio' });
  }
});

/*
//CALCULAR DESPERDICIO SEMANAL==========================================================================
app.get('/desperdicio-semanal', authenticateToken, async (req, res) => {
  try {
    const almacen = await db.collection('almacen').findOne({ usuarioId: new ObjectId(req.user.id) });
    let desperdicioProteinas = 0, desperdicioCarbohidratos = 0;

    almacen.ingredientes.forEach(ingrediente => {
      if (ingrediente.perecedero && new Date() - new Date(ingrediente.fechaIngreso) > 7 * 24 * 60 * 60 * 1000) {
        desperdicioProteinas += ingrediente.proteinas;
        desperdicioCarbohidratos += ingrediente.carbohidratos;
      }
    });

    await db.collection('registroConsumo').insertOne({
      usuarioId: req.user.id,
      fecha: new Date(),
      proteinas: 0,
      carbohidratos: 0,
      desperdicio: { proteinas: desperdicioProteinas, carbohidratos: desperdicioCarbohidratos }
    });

    res.status(200).json({ message: 'Desperdicio semanal calculado', desperdicioProteinas, desperdicioCarbohidratos });
  } catch (error) {
    res.status(500).json({ error: 'Error al calcular desperdicio semanal' });
  }
});
*/


//=============================================NOTICIAS DE COMIDA=======================================
// Ruta para obtener noticias
app.get('/noticias', async (req, res) => {
  try {
    const noticias = await getNoticias();
    res.json(noticias);
  } catch (error) {
    res.status(500).send('Error al obtener noticias');
  }
});

//============================================NOTIFICACIONES=============================================
//=======================================================================================================
// Se envia una notificacion al usuario con los nombres de los ingredientes que se han agotado en su almacen 
//============================================GENERAR NOTIFICACIONES=================================
app.post('/notificaciones/generar', authenticateToken, async (req, res) => {
  try {
    const db = await connectToDatabase();
    const usuarioId = new ObjectId(req.user.id);
    const almacen = await db.collection('almacen').findOne({ usuarioId });
    
    // Verificar si el almacén no existe o está vacío
    if (!almacen || !almacen.ingredientes || almacen.ingredientes.length === 0) {
      await db.collection('notificaciones').insertOne({
        usuarioId,
        ingredientes: [],
        fecha: new Date(),
        leido: false,
        mensaje: 'No tiene ingredientes ingresados en su almacén',
      });
      return res.status(200).json({ message: 'Notificación generada: No tiene ingredientes en el almacén' });
    }

    // Filtrar ingredientes agotados
    const ingredientesAgotados = almacen.ingredientes
      .filter(ingrediente => ingrediente.cantidad === 0)
      .map(ingrediente => ingrediente.nombre);  // Solo nombres

    if (ingredientesAgotados.length > 0) {
      // Guarda la notificación en la colección de notificaciones
      await db.collection('notificaciones').insertOne({
        usuarioId,
        ingredientes: ingredientesAgotados,
        fecha: new Date(),
        leido: false,
        mensaje: `Tienes ingredientes agotados: ${ingredientesAgotados.join(', ')}`,
      });
      return res.status(200).json({ message: 'Notificación generada por ingredientes agotados' });
    } else {
      return res.status(200).json({ message: 'No tienes ingredientes agotados' });
    }
  } catch (error) {
    console.error('Error al generar notificación:', error.message);
    res.status(500).json({ error: 'Error al generar notificación' });
  }
});

// Ruta para obtener las notificaciones del usuario
app.get('/notificaciones', authenticateToken, async (req, res) => {
  try {
    const db = await connectToDatabase();
    const usuarioId = new ObjectId(req.user.id);

    // Obtener las notificaciones de la colección 'notificaciones' para el usuario autenticado
    const notificaciones = await db.collection('notificaciones')
      .find({ usuarioId })
      .sort({ fecha: -1 }) // Ordenar por fecha, las más recientes primero
      .toArray();

    res.status(200).json({ notificaciones });
  } catch (error) {
    console.error('Error al obtener las notificaciones:', error.message);
    res.status(500).json({ error: 'Error al obtener las notificaciones' });
  }
});


//=====ELIMINAR NOTIFICACIÓN
app.delete('/notificaciones/:id', authenticateToken, async (req, res) => {
  try {
    const db = await connectToDatabase();
    const { id } = req.params;
    const result = await db.collection('notificaciones').deleteOne({ _id: new ObjectId(id) });
    
    if (result.deletedCount === 0) {
      return res.status(404).json({ message: 'Notificación no encontrada' });
    }

    res.status(200).json({ message: 'Notificación eliminada con éxito' });
  } catch (error) {
    console.error('Error al eliminar notificación:', error.message);
    res.status(500).json({ error: 'Error al eliminar notificación' });
  }
});

//=====================================VALORAR RECETA==========================================
//==============================================================================================
app.post('/receta/valorar', authenticateToken, async (req, res) => {
  const { recipeId, valoracion, nombre, porciones, tiempo, imageUrl } = req.body;

  // Verificar que la valoración sea un número entero entre 1 y 5
  if (!recipeId || !Number.isInteger(valoracion) || valoracion < 1 || valoracion > 5) {
    return res.status(400).json({ message: 'La valoración debe estar entre 1 y 5 y debe ser un número entero' });
  }

  try {
    const db = await connectToDatabase();
    const usuarioId = new ObjectId(req.user.id);

    // Guardar o actualizar la receta valorada en la colección `recetasValoradas`
    await db.collection('recetasValoradas').updateOne(
      { recipeId, usuarioId },  // Clave compuesta por `recipeId` y `usuarioId` para permitir valoraciones únicas por usuario y receta
      { 
        $set: { 
          valoracion,
          nombre,
          porciones,
          tiempo,
          imageUrl, // Guardar la URL de la imagen
          fechaValoracion: new Date()
        }
      },
      { upsert: true }
    );

    res.status(200).json({ message: 'Receta valorada exitosamente' });
  } catch (error) {
    console.error('Error al valorar receta:', error.message);
    res.status(500).json({ message: 'Error al valorar la receta' });
  }
});

//==================================OBTENER RECETAS MEJOR VALORADAS==================================
//===============================================================================================
app.get('/recetas/mejor-valoradas', authenticateToken, async (req, res) => {
  try {
    const db = await connectToDatabase();

    // Obtener las recetas con promedio de valoraciones y cantidad de reseñas
    const recetas = await db.collection('recetasValoradas')
      .aggregate([
        {
          $group: {
            _id: "$recipeId", // Agrupar por ID de la receta
            nombre: { $first: "$nombre" },
            imageUrl: { $first: "$imageUrl" },
            porciones: { $first: "$porciones" },
            tiempo: { $first: "$tiempo" },
            averageRating: { $avg: "$valoracion" }, // Calcular el promedio de valoraciones
            reviews: { $sum: 1 } // Contar la cantidad de reseñas
          }
        },
        {
          $sort: { averageRating: -1, reviews: -1 } // Ordenar por promedio y luego por cantidad de reseñas
        },
        {
          $limit: 10 // Limitar el resultado a las 10 mejores recetas
        }
      ])
      .toArray();

    res.status(200).json(recetas);
  } catch (error) {
    console.error('Error al obtener recetas mejor valoradas:', error.message);
    res.status(500).json({ message: 'Error al obtener recetas mejor valoradas' });
  }
});

//==================================OBTENER RECETAS VALORADAS RECIENTEMENTE==================================
//===============================================================================================
// Ruta para obtener las recetas valoradas recientemente
app.get('/recetas/valoradas-recientes', authenticateToken, async (req, res) => {
  try {
    const db = await connectToDatabase();
    const userId = new ObjectId(req.user.id); // Convierte el ID del usuario

    // Buscar recetas valoradas por el usuario, ordenadas por fecha reciente
    const recetas = await db.collection('recetasValoradas')
      .find({ usuarioId: userId })
      .sort({ fechaValoracion: -1 }) // Ordenar por fecha más reciente
      .limit(10) // Limitar a las 10 más recientes
      .project({ recipeId: 1, nombre: 1, imageUrl: 1, valoracion: 1, porciones: 1, tiempo: 1 }) // Seleccionar campos necesarios
      .toArray();

    // Si no hay recetas valoradas
    if (!recetas || recetas.length === 0) {
      return res.status(200).json({
        message: 'No hay recetas valoradas recientemente.',
        recetas: [],
      });
    }

    // Respuesta con las recetas encontradas
    res.status(200).json({
      message: 'Recetas valoradas obtenidas exitosamente.',
      recetas,
    });
  } catch (error) {
    console.error('Error al obtener recetas valoradas recientemente:', error);
    res.status(500).json({ message: 'Error al obtener recetas valoradas.', error: error.message });
  }
});





//==============================GUARDAR/ELIMINAR RECETA=======================================
//============================================================================================
// Guardar receta en favoritos
app.post('/recetas/guardar', authenticateToken, async (req, res) => {
  const { recipeId } = req.body;

  try {
    const db = await connectToDatabase();

    // Verificar si la receta ya está guardada en favoritos
    const recetaExistente = await db.collection('recetasGuardadas').findOne({
      usuarioId: new ObjectId(req.user.id),
      'receta.recipeId': Number(recipeId)
    });

    if (recetaExistente) {
      // Responde con estado 200 e indica que ya estaba guardada
      return res.status(200).json({
        message: 'Esta receta ya fue guardada en favoritos anteriormente',
        alreadySaved: true
      });
    }

    // Buscar la receta en la base de datos de recetas
    const receta = await db.collection('recetas').findOne({ recipeId });

    if (!receta) {
      return res.status(404).json({ message: 'Receta no encontrada en la base de datos' });
    }

    // Guardar la receta en favoritos
    await db.collection('recetasGuardadas').insertOne({
      usuarioId: new ObjectId(req.user.id),
      receta,
    });

    res.status(200).json({
      message: 'Receta guardada exitosamente',
      alreadySaved: false,
      receta
    });
  } catch (error) {
    console.error('Error al guardar la receta:', error.message);
    res.status(500).json({ message: 'Error al guardar la receta' });
  }
});




//VER RECETAS GUARDADAS 
// Ruta para obtener las recetas guardadas del usuario (Paginacion para mejorar rendimiento)
app.get('/recetas/guardadas', authenticateToken, async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;

  try {
    const db = await connectToDatabase();

    const recetasGuardadas = await db.collection('recetasGuardadas')
      .find({ usuarioId: new ObjectId(req.user.id) })
      .skip((page - 1) * limit)
      .limit(limit)
      .toArray();

    if (!recetasGuardadas || recetasGuardadas.length === 0) {
      // Responder con un mensaje informativo en lugar de un error
      return res.status(200).json({ recetas: [], message: 'No tienes recetas guardadas' });
    }

    // Mostrar en consola las recetas obtenidas para verificar
    console.log("Recetas guardadas obtenidas:", recetasGuardadas);

    res.status(200).json({ recetas: recetasGuardadas });
  } catch (error) {
    console.error('Error al obtener las recetas guardadas:', error.message);
    res.status(500).json({ message: 'Error al obtener las recetas guardadas' });
  }
});

// ELIMINAR RECETA GUARDADA
app.delete('/receta/eliminar-guardada', authenticateToken, async (req, res) => {
  const { recipeId } = req.body;

  if (!recipeId) {
    return res.status(400).json({ message: 'Se requiere un ID de receta' });
  }

  try {
    const db = await connectToDatabase();
    const usuarioId = new ObjectId(req.user.id);

    // Asegúrate de comparar `recipeId` como número.
    const result = await db.collection('recetasGuardadas').deleteOne({
      usuarioId: usuarioId,
      'receta.recipeId': Number(recipeId) // Convertir a número para la comparación
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({ message: 'Receta no encontrada en la lista de guardadas' });
    }

    res.status(200).json({ message: 'Receta eliminada exitosamente' });
  } catch (error) {
    console.error('Error al eliminar receta guardada:', error.message);
    res.status(500).json({ message: 'Error al eliminar la receta guardada' });
  }
});

//=====================================COMPARTIR RECETA========================================
//==============================================================================================
app.get('/receta/compartir/:id', authenticateToken, async (req, res) => {
  const recipeId = req.params.id;

  try {
    const db = await connectToDatabase();
    const receta = await obtenerRecetaDeSpoonacular(recipeId);

    if (!receta) {
      return res.status(404).json({ message: 'Receta no encontrada' });
    }

    // Traducir el título de la receta al español usando la API de Google Translate
    const tituloTraducido = await translateText(receta.title, 'es');

    const link = `https://api.whatsapp.com/send?text=¡Mira esta receta increíble! ${tituloTraducido} - ${receta.sourceUrl}`;
    
    res.status(200).json({ message: 'Enlace generado exitosamente', link });
  } catch (error) {
    console.error('Error al generar el enlace para compartir:', error.message);
    res.status(500).json({ message: 'Error al generar el enlace para compartir' });
  }
});

//========================================SALUD=============================================
// Ruta para obtener el perfil de salud del usuario
app.get('/perfil/health', authenticateToken, async (req, res) => {
  try {
    const usuario = await usersCollection.findOne(
      { _id: new ObjectId(req.user.id) },
      { projection: { healthData: 1 } } // Solo devolver el healthData
    );

    if (!usuario) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    // Si no hay datos de salud, devolver un objeto vacío en lugar de null
    const healthData = usuario.healthData || {
      weight: null,
      height: null,
      imc: null,
      dietRecommendation: null,
      caloricNeeds: null,
      tmb: null,
    };

    res.status(200).json({
      message: 'Datos de salud obtenidos exitosamente.',
      healthData,
    });
  } catch (error) {
    console.error('Error al obtener el perfil de salud:', error.message);
    res.status(500).json({ message: 'Error al obtener el perfil de salud.', error: error.message });
  }
});


// Ruta para actualizar el perfil de salud del usuario (solo para usuarios premium)
app.put('/perfil/health', authenticateToken, async (req, res) => {
  const { weight, height } = req.body;

  // Validar que los datos requeridos están presentes
  if (!weight || !height) {
    return res.status(400).json({ message: 'Debe proporcionar peso y altura para calcular el IMC.' });
  }

  try {
    // Obtener el usuario actual
    const usuario = await usersCollection.findOne({ _id: new ObjectId(req.user.id) });

    // Verificar si el usuario es premium
    if (!usuario || !usuario.premium) {
      return res.status(403).json({ message: 'Esta funcionalidad es exclusiva para usuarios premium.' });
    }

    // Calcular el IMC
    const imc = (weight / ((height / 100) ** 2)).toFixed(2);

    // Generar la recomendación dietética basada en el IMC
    let dietRecommendation = '';
    if (imc < 18.5) {
      dietRecommendation = 'Dieta alta en calorías';
    } else if (imc >= 18.5 && imc < 24.9) {
      dietRecommendation = 'Dieta balanceada';
    } else if (imc >= 25 && imc < 29.9) {
      dietRecommendation = 'Dieta baja en calorías';
    } else {
      dietRecommendation = 'Dieta para reducción de peso';
    }

    // Actualizar el perfil de salud del usuario en la base de datos
    const result = await usersCollection.updateOne(
      { _id: new ObjectId(req.user.id) },
      {
        $set: {
          healthData: {
            weight,
            height,
            imc: parseFloat(imc),
            dietRecommendation,
          },
        },
      },
      { upsert: true } // Crear healthData si no existe
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado o sin cambios.' });
    }

    res.status(200).json({
      message: 'Perfil de salud actualizado exitosamente.',
      healthData: {
        weight,
        height,
        imc,
        dietRecommendation,
      },
    });
  } catch (error) {
    console.error('Error al actualizar el perfil de salud:', error.message);
    res.status(500).json({ message: 'Error al actualizar el perfil de salud.', error: error.message });
  }
});

// Ruta para obtener y guardar las calorías recomendadas en el perfil de salud
app.post('/perfil/calorias', authenticateToken, async (req, res) => {
  const { weight, height, age, gender, activityLevel } = req.body;

  // Validar que los datos requeridos están presentes
  if (!weight || !height || !age || !gender || !activityLevel) {
    return res.status(400).json({ message: 'Debe proporcionar peso, altura, edad, género y nivel de actividad.' });
  }

  try {
    // Calcular la Tasa Metabólica Basal (TMB)
    let tmb;
    if (gender.toLowerCase() === 'male') {
      tmb = 10 * weight + 6.25 * height - 5 * age + 5;
    } else if (gender.toLowerCase() === 'female') {
      tmb = 10 * weight + 6.25 * height - 5 * age - 161;
    } else {
      return res.status(400).json({ message: 'Género inválido. Use "male" o "female".' });
    }

    // Multiplicar la TMB por el factor de actividad física
    const activityFactors = {
      sedentary: 1.2,
      light: 1.375,
      moderate: 1.55,
      active: 1.725,
      very_active: 1.9,
    };

    const factor = activityFactors[activityLevel.toLowerCase()];
    if (!factor) {
      return res.status(400).json({ message: 'Nivel de actividad inválido.' });
    }

    const caloricNeeds = (tmb * factor).toFixed(0); // Calorías diarias recomendadas

    // Guardar las calorías en el perfil de salud del usuario
    const result = await usersCollection.updateOne(
      { _id: new ObjectId(req.user.id) },
      {
        $set: {
          'healthData.caloricNeeds': parseInt(caloricNeeds),
          'healthData.tmb': parseFloat(tmb),
          'healthData.age': age,
          'healthData.gender': gender,
          'healthData.activityLevel': activityLevel,
        },
      }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado o sin cambios.' });
    }

    res.status(200).json({
      message: 'Calorías calculadas y guardadas exitosamente.',
      caloricNeeds,
      tmb,
    });
  } catch (error) {
    console.error('Error al calcular las calorías:', error.message);
    res.status(500).json({ message: 'Error al calcular las calorías.', error: error.message });
  }
});

// Ruta protegida para acceder al perfil de usuario solo con token válido
app.get('/perfil', authenticateToken, async (req, res) => {
  try {
    const usuario = await usersCollection.findOne({ _id: req.user.id });
    if (!usuario) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    res.status(200).json({ 
      nombre: usuario.nombre,
      email: usuario.email,
      healthData: usuario.healthData 
    });
  } catch (error) {
    console.error('Error al obtener el perfil del usuario:', error);
    res.status(500).json({ message: 'Error al obtener el perfil' });
  }
});

// ruta admin -- dejar aca
const cors = require('cors');
app.use(cors({
  origin: 'http://localhost:3000', // Cambia al origen de tu frontend
  credentials: true, // Si necesitas enviar cookies u otros encabezados sensibles
}));
const adminRoutes = require('./adminRoutes');
app.use('/api/admin', adminRoutes);
// Asegúrate de que Express sirva la carpeta "uploads" de forma pública
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ruta de imagen
const imageProxy = require('./imageProxy'); 
// Usa la nueva ruta
app.use('/api', imageProxy);

//===============================================================CONSULTAS=====================================
// Ruta para crear una nueva consulta
app.post('/reclamos', authenticateToken, async (req, res) => {
  console.log('Datos recibidos:', req.body); // Depuración
  console.log('Usuario autenticado:', req.user); // Depuración

  // Esquema de validación con Joi
  const schema = Joi.object({
    titulo: Joi.string().required().messages({
      'any.required': 'El título es obligatorio',
      'string.empty': 'El título no puede estar vacío',
    }),
    destinatario: Joi.string().valid('admin', 'nutricionista').required().messages({
      'any.required': 'El destinatario es obligatorio',
      'any.only': 'El destinatario debe ser "admin" o "nutricionista"',
    }),
    comentario: Joi.string().required().messages({
      'any.required': 'El comentario es obligatorio',
      'string.empty': 'El comentario no puede estar vacío',
    }),
  });

  // Validar los datos del cuerpo
  const { error } = schema.validate(req.body);
  if (error) {
    console.error('Error de validación:', error.details[0].message); // Depuración
    return res.status(400).json({ message: error.details[0].message });
  }

  const { titulo, destinatario, comentario } = req.body;

  try {
    const nuevaConsulta = {
      usuarioId: new ObjectId(req.user.id),
      nombre: req.user.nombre,
      email: req.user.email,
      titulo,
      destinatario,
      comentario,
      estado: 'Pendiente',
      fechaCreacion: new Date(),
      respuesta: null,
    };

    console.log('Insertando consulta:', nuevaConsulta); // Depuración

    const db = await connectToDatabase();
    await db.collection('reclamos').insertOne(nuevaConsulta);

    res.status(201).json({ message: 'Consulta creada exitosamente', consulta: nuevaConsulta });
  } catch (error) {
    console.error('Error al crear la consulta:', error.message); // Depuración
    res.status(500).json({ message: 'Error al crear la consulta', error: error.message });
  }
});


// Ruta para obtener las consultas del usuario autenticado
app.get('/reclamos/mis-consultas', authenticateToken, async (req, res) => {
  try {
    const db = await connectToDatabase();
    const consultas = await db
      .collection('reclamos')
      .find({ usuarioId: new ObjectId(req.user.id) })
      .toArray();

    res.status(200).json(consultas);
  } catch (error) {
    console.error('Error al obtener las consultas del usuario:', error.message);
    res.status(500).json({ message: 'Error al obtener las consultas del usuario', error: error.message });
  }
});

app.put('/reclamos/marcar-leido', authenticateToken, async (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).json({ message: 'Se requiere el ID de la consulta' });

  try {
    const result = await db.collection('reclamos').updateOne(
      { _id: new ObjectId(id) },
      { $set: { leido: true } }
    );
    if (result.modifiedCount === 0) return res.status(404).json({ message: 'Consulta no encontrada' });
    res.status(200).json({ message: 'Consulta marcada como leída' });
  } catch (error) {
    res.status(500).json({ message: 'Error al marcar la consulta como leída', error: error.message });
  }
});

//=======================================VALIDACION PREMIUM
function checkPremium(req, res, next) {
  if (!req.user.premium) {
    return res.status(403).json({ message: 'Acceso restringido a usuarios premium.' });
  }
  next();
}

// Ruta accesible solo para usuarios premium
app.get('/funcionalidad-premium', authenticateToken, checkPremium, (req, res) => {
  res.json({ message: 'Bienvenido a la funcionalidad premium.' });
});

app.put('/usuario/premium', authenticateToken, async (req, res) => {
  const { premium } = req.body;

  if (typeof premium !== 'boolean') {
    return res.status(400).json({ message: 'El estado premium debe ser un valor booleano.' });
  }

  try {
    const result = await usersCollection.updateOne(
      { _id: new ObjectId(req.user.id) },
      { $set: { premium } }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado o sin cambios.' });
    }

    res.status(200).json({ message: `Estado premium actualizado a ${premium}` });
  } catch (error) {
    console.error('Error al actualizar estado premium:', error.message);
    res.status(500).json({ message: 'Error al actualizar estado premium.', error: error.message });
  }
});

//===================================SIMULACION PAGO PREMIUM
app.post('/simular-pago', authenticateToken, async (req, res) => {
  try {
    const result = await usersCollection.updateOne(
      { _id: new ObjectId(req.user.id) },
      { $set: { premium: true } }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    res.status(200).json({ message: 'Usuario ahora es premium.' });
  } catch (error) {
    console.error('Error al simular pago:', error.message);
    res.status(500).json({ message: 'Error al simular pago.', error: error.message });
  }
});

//================================ALERGIAS===================
//Obtener alergias
app.get('/perfil/allergies', authenticateToken, async (req, res) => {
  try {
    const usuario = await usersCollection.findOne(
      { _id: new ObjectId(req.user.id) },
      { projection: { allergies: 1 } }
    );

    if (!usuario) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    res.status(200).json({
      message: 'Alergias obtenidas exitosamente.',
      allergies: usuario.allergies || []
    });
  } catch (error) {
    console.error('Error al obtener alergias:', error.message);
    res.status(500).json({ message: 'Error al obtener alergias.', error: error.message });
  }
});

//Guardar alergias
// Ruta para actualizar las alergias del usuario
app.post('/perfil/alergias', authenticateToken, async (req, res) => {
  try {
    const userId = new ObjectId(req.user.id);
    const { allergies } = req.body;

    // Validar que `allergies` sea un arreglo
    if (!Array.isArray(allergies)) {
      return res.status(400).json({ message: 'Las alergias deben ser un arreglo.' });
    }

    // Actualizar el campo `allergies` del usuario
    await usersCollection.updateOne(
      { _id: userId },
      { $set: { allergies } }
    );

    res.status(200).json({ message: 'Alergias actualizadas exitosamente.' });
  } catch (error) {
    console.error('Error al actualizar alergias:', error.message);
    res.status(500).json({ message: 'Error al actualizar alergias.' });
  }
});
