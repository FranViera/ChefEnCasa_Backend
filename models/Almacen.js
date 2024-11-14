const { ObjectId } = require('mongodb');

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


// Definir el esquema del almacén (usando una estructura similar a la del usuario)
const almacenSchema = {
  usuarioId: ObjectId, // ID del usuario que posee este almacén
  ingredientes: [
    {
      nombre: String,      // Nombre del ingrediente
      cantidad: Number,    // Cantidad de ingrediente en el almacén (en medidas como gramos)
      fechaIngreso: { type: Date, default: Date.now }, // Fecha de ingreso
      perecedero: Boolean  // Si el ingrediente es perecedero
    }
  ]
};

// Crear una función para insertar un nuevo almacén (o actualizar uno existente)
async function crearOActualizarAlmacen(db, usuarioId, ingredientes) {
  try {
    const almacen = await db.collection('almacen').findOne({ usuarioId: new ObjectId(usuarioId) });

    if (!almacen) {
      // Crear un nuevo almacén si no existe
      await db.collection('almacen').insertOne({
        usuarioId: new ObjectId(usuarioId),
        ingredientes: ingredientes.map(ing => ({
          nombre: ing.nombre.toLowerCase(),
          cantidad: convertirMedida(ing.cantidad, ing.unidad), // Convertir a gramos o mililitros
          img: ing.img || '', // Incluir la imagen si está disponible
          fechaIngreso: new Date(),
          perecedero: ing.perecedero || false
        }))
      });
    } else {
      // Si el almacén existe, actualizamos o añadimos ingredientes
      ingredientes.forEach(ing => {
        const almacenIngrediente = almacen.ingredientes.find(item => item.nombre === ing.nombre.toLowerCase());

        if (almacenIngrediente) {
          // Si el ingrediente ya existe, sumamos la cantidad (convertida)
          almacenIngrediente.cantidad += convertirMedida(ing.cantidad, ing.unidad);
          // Actualizar la imagen si se proporciona una nueva
          almacenIngrediente.img = ing.img || almacenIngrediente.img;
        } else {
          // Si es un nuevo ingrediente, lo añadimos
          almacen.ingredientes.push({
            nombre: ing.nombre.toLowerCase(),
            cantidad: convertirMedida(ing.cantidad, ing.unidad),
            img: ing.img || '', // Incluir la imagen si está disponible
            fechaIngreso: new Date(),
            perecedero: ing.perecedero || false
          });
        }
      });

      // Actualizar el almacén en la base de datos
      await db.collection('almacen').updateOne(
        { usuarioId: new ObjectId(usuarioId) },
        { $set: { ingredientes: almacen.ingredientes } }
      );
    }

  } catch (error) {
    throw new Error('Error al crear o actualizar el almacén: ' + error.message);
  }
}

// Función para buscar un ingrediente por su nombre
async function buscarIngredientePorNombre(db, usuarioId, nombreIngrediente) {
  const almacen = await db.collection('almacen').findOne({ usuarioId: new ObjectId(usuarioId) });
  if (!almacen) {
    return null;
  }
  return almacen.ingredientes.find(item => item.nombre === nombreIngrediente.toLowerCase());
}

module.exports = { almacenSchema, crearOActualizarAlmacen, buscarIngredientePorNombre };


