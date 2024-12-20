const functions = require('firebase-functions');
const fileParser = require('express-multipart-file-parser');
const bodyParser = require('body-parser');
const { Readable } = require('stream');
const admin = require("firebase-admin");
const express = require('express');
const cors = require('cors');
const { v4: uuidv4 } = require("uuid"); // Importar uuid para generar identificadores únicos
const path = require("path"); // Impo

admin.initializeApp({
    credential: admin.credential.cert('./credentials.json'),
    databaseURL: 'https://fb-api-720ab.firebaseio.com',
    storageBucket: "fb-api-720ab.firebasestorage.app",
});

const app = express();

const db = admin.firestore();

console.log("FieldValue test:", admin.firestore.FieldValue);

// Middlewares
app.use(fileParser);
app.use(cors({ origin: true }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json()); // Para manejar JSON en el cuerpo de las solicitudes
const bucket = admin.storage().bucket(); // Asegúrate de definir esto al inicio



// Ruta para subir imágenes relacionadas con eventos
app.post("/api/files/event/header-image", async (req, res) => {
    try {
      if (!req.files || req.files.length === 0) {
        return res.status(400).json({ error: "No se envió ningún archivo." });
      }
  
      const file = req.files[0];
      console.log("Archivo recibido:", file);
  
      // Obtener la extensión del archivo
      const extension = path.extname(file.originalname).toLowerCase();
      if (![".jpg", ".jpeg", ".png", ".gif"].includes(extension)) {
        return res.status(400).json({ error: "Formato de archivo no soportado." });
      }
  
      // Generar identificador único con extensión
      const uniqueId = `${uuidv4()}${extension}`;
      const filePath = `event/images/${uniqueId}`;
  
      // Subir el archivo a Firebase Storage
      const fileRef = bucket.file(filePath);
      const fileStream = Readable.from(file.buffer);
  
      const writeStream = fileRef.createWriteStream({
        metadata: { contentType: file.mimetype },
      });
  
      fileStream.pipe(writeStream)
        .on("error", (error) => {
          console.error("Error al subir el archivo:", error);
          res.status(500).json({ error: "Error al subir el archivo." });
        })
        .on("finish", () => {
          console.log(`Archivo subido: ${filePath}`);
          res.status(200).json({
            message: "Archivo subido correctamente.",
            image: uniqueId, // Devolver el identificador único del archivo
          });
        });
    } catch (error) {
      console.error("Error inesperado:", error);
      res.status(500).json({ error: "Ocurrió un error inesperado." });
    }
  });
  
  // Ruta para obtener una imagen por su identificador
  app.get("/api/files/event/header-image/:imageName", async (req, res) => {
    const { imageName } = req.params;
  
    try {
      const fileRef = bucket.file(`event/images/${imageName}`);
      const [exists] = await fileRef.exists();
  
      if (!exists) {
        return res.status(404).json({ error: "Archivo no encontrado." });
      }
  
      const [url] = await fileRef.getSignedUrl({
        action: "read",
        expires: "03-01-2030", // URL válida hasta esta fecha
      });
  
      res.redirect(url); // Redirigir a la URL pública
    } catch (error) {
      console.error("Error al obtener el archivo:", error);
      res.status(500).json({ error: "Error al obtener el archivo." });
    }
  });


  // Ruta para subir documentos relacionados con eventos
app.post("/api/files/event/documents/:userId", async (req, res) => {
    try {
        const { userId } = req.params;

        if (!req.files || req.files.length === 0) {
            return res.status(400).json({ error: "No se enviaron archivos." });
        }

        if (!userId) {
            return res.status(400).json({ error: "Se requiere un identificador de usuario." });
        }

        const uploadedFiles = [];

        for (const file of req.files) {
            console.log("Archivo recibido:", file);

            // Obtener la extensión del archivo
            const extension = path.extname(file.originalname).toLowerCase();
            if (![".jpg", ".jpeg", ".png", ".gif", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt"].includes(extension)) {
                return res.status(400).json({ error: `Formato de archivo no soportado: ${file.originalname}` });
            }

            // Generar identificador único con extensión
            const uniqueId = `${uuidv4()}${extension}`;
            const filePath = `event/documents/user/${userId}/${uniqueId}`;

            // Subir el archivo a Firebase Storage
            const fileRef = bucket.file(filePath);
            const fileStream = Readable.from(file.buffer);

            const writeStream = fileRef.createWriteStream({
                metadata: { contentType: file.mimetype },
            });

            await new Promise((resolve, reject) => {
                fileStream.pipe(writeStream)
                    .on("error", (error) => {
                        console.error(`Error al subir el archivo ${file.originalname}:`, error);
                        reject(error);
                    })
                    .on("finish", () => {
                        console.log(`Archivo subido: ${filePath}`);
                        uploadedFiles.push(uniqueId); // Guardar el identificador único
                        resolve();
                    });
            });
        }

        res.status(200).json({
            message: "Archivos subidos correctamente.",
            files: uploadedFiles, // Devolver la lista de identificadores únicos de los archivos subidos
        });
    } catch (error) {
        console.error("Error inesperado:", error);
        res.status(500).json({ error: "Ocurrió un error inesperado al subir los archivos." });
    }
});



// Endpoint de registro de usuario
app.post('/api/auth/register', async (req, res) => {
    const { fullName, companyName, nif, email, telefono, sector, aceptaTerminos, aceptaComunicaciones, roles } = req.body;

    // Rol por defecto
    const defaultRole = 'user';

    // Si no se proporciona un rol, asignar el rol por defecto
    let rolesArray = Array.isArray(roles) && roles.length > 0 ? roles : [defaultRole];

    // Asegurarse de que el rol por defecto esté presente si no se envía ningún rol
    if (rolesArray.length === 0) {
        rolesArray = [defaultRole];
    } else if (!rolesArray.includes(defaultRole)) {
        // Asegurarse de que no se dupliquen roles
        rolesArray = [...new Set(rolesArray)]; // Eliminar duplicados
    }

    try {
        // Verificar si el correo electrónico ya está registrado en Firebase Authentication
        const userExists = await admin.auth().getUserByEmail(email).catch(() => null);

        if (userExists) {
            // Si el usuario ya existe, responder con un error específico
            return res.status(409).json({
                message: 'El correo electrónico ya está registrado. Por favor, utiliza otro correo.'
            });
        }

        // Crear el usuario en Firebase Authentication (sin contraseña)
        const userRecord = await admin.auth().createUser({
            email: email,
            displayName: fullName,
        });

        // Guardar información adicional en Firestore
        await db.collection('users').doc(userRecord.uid).set({
            fullName: fullName,
            companyName: companyName,
            nif: nif,
            email: email,
            telefono: telefono,
            sector: sector,
            isActive: true,
            aceptaTerminos: aceptaTerminos,
            aceptaComunicaciones: aceptaComunicaciones,
            roles: rolesArray, // Almacenar los roles (ya sea proporcionado o por defecto)
        });

        // Generar un token personalizado
        const token = await admin.auth().createCustomToken(userRecord.uid);

        // Responder con el formato deseado
        res.status(201).json({
            id: userRecord.uid, // UID del usuario
            fullName: fullName, // Nombre completo del usuario
            companyName: companyName, // Nombre de la compañía
            nif: nif, // nif del usuario
            email: email, // Correo electrónico del usuario
            telefono: telefono, // Teléfono del usuario
            sector: sector, // sector del usuario
            aceptaTerminos: aceptaTerminos,
            aceptaComunicaciones: aceptaComunicaciones,
            isActive: true, // Estado del usuario
            roles: rolesArray, // Roles del usuario
            token: token, // Token JWT generado
        });
        
    } catch (error) {
        console.error('Error creando usuario:', error);
        res.status(500).send(error.message);
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email } = req.body;

    try {
        // Obtener el usuario por email
        const userRecord = await admin.auth().getUserByEmail(email);

        // Generar un token personalizado
        const customToken = await admin.auth().createCustomToken(userRecord.uid);

        // Recuperar la información adicional del usuario en Firestore
        const userDoc = await db.collection('users').doc(userRecord.uid).get();

        if (!userDoc.exists) {
            return res.status(404).json({ message: "Usuario no encontrado en Firestore" });
        }

        // Responder con los datos del usuario y el custom token
        const userData = userDoc.data();
        res.status(200).json({
            id: userRecord.uid,
            fullName: userData.fullName,
            email: userRecord.email,
            telefono: userRecord.telefono || null,
            roles: userData.roles,
            token: customToken, // Devuelve el custom token aquí
            // Puedes agregar más datos del usuario según tus necesidades
        });
    } catch (error) {
        console.error("Error en el login:", error);
        res.status(500).json({ error: error.message });
    }
});

// Endpoint de verificación de estado
app.get('/auth/check-status', async (req, res) => {
    const idToken = req.headers.authorization?.split('Bearer ')[1];

    if (!idToken) {
        return res.status(401).json({ message: 'Token no proporcionado' });
    }

    try {
        // Verifica el ID Token del usuario
        const decodedToken = await admin.auth().verifyIdToken(idToken);

        // Si la verificación es exitosa, puedes enviar la información del usuario de vuelta
        res.status(200).json({
            uid: decodedToken.uid,
            email: decodedToken.email,
            telefono: decodedToken.telefono || null,
            roles: decodedToken.roles || ['user'], // Puedes incluir roles si los tienes en los claims
            authenticated: true,
            message: 'Usuario autenticado correctamente'
        });
    } catch (error) {
        console.error('Error verificando token:', error);
        res.status(401).json({ message: 'Token no válido o sesión caducada' });
    }
});




const authenticateUser = async (req, res, next) => {
    const idToken = req.headers.authorization?.split('Bearer ')[1];
    if (!idToken) {
        return res.status(401).json({ message: "Token no proporcionado." });
    }

    try {
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        req.user = { uid: decodedToken.uid };
        next();
    } catch (error) {
        res.status(401).json({ message: "Token inválido o expirado." });
    }
};

// Ruta para obtener datos de un usuario por su UID
app.get('/api/users/:uid',  async (req, res) => {
    const { uid } = req.params; // Obtener el UID de los parámetros de la URL
  
    try {
      // Obtener los datos del usuario desde Firestore
      const userDoc = await db.collection('users').doc(uid).get();
  
      if (!userDoc.exists) {
        return res.status(404).json({ message: 'Usuario no encontrado.' });
      }
  
      // Devolver los datos del usuario
      res.status(200).json({
        id: uid,
        ...userDoc.data(), // Incluir todos los datos almacenados en Firestore
      });
    } catch (error) {
      console.error('Error al obtener el usuario por UID:', error);
      res.status(500).json({ message: 'Error al obtener el usuario.' });
    }
  });

app.post('/api/create-events', authenticateUser, async (req, res) => {
    const {
        name,
        description,
        startDate,
        endDate,
        startTime,
        endTime,
        differentSchedulesPerDay,
        location,
        headerImage,
        inscriptionStartDate,
        inscriptionEndDate,
        inscriptionStartTime,
        inscriptionEndTime,
        isPublic,
        capacity,
        inscriptionCost,
        paymentMethods,
        agenda,
        additionalInformation,
        attachedDocuments,
        ageRestriction,
        contactName,
        contactPhone,
        contactEmail,
        webpage,
        instagram,
        facebook,
        youtube,
        linkedin,
    } = req.body;

    if (!req.user || !req.user.uid) {
        return res.status(403).json({ message: "Usuario no autenticado." });
    }

    try {
        const event = {
            createdBy: req.user.uid,
            name, // Nombre oficial del evento
            description, // Descripción del evento
            startDate, // Fecha de inicio del evento
            endDate, // Fecha de finalización del evento
            startTime, // Hora de inicio del evento
            endTime, // Hora de finalización del evento
            differentSchedulesPerDay: differentSchedulesPerDay || false, // Si hay horarios diferentes por día
            location, // Ubicación del evento
            headerImage: headerImage || null, // URL de la imagen de cabecera del evento
            inscriptionStartDate, // Fecha de inicio de la inscripción
            inscriptionEndDate, // Fecha de finalización de la inscripción
            inscriptionStartTime, // Hora de inicio de la inscripción
            inscriptionEndTime, // Hora de finalización de la inscripción
            isPublic: typeof isPublic !== 'undefined' ? isPublic : true, // Si el evento es público o privado
            capacity: capacity || 0, // Capacidad máxima del evento
            inscriptionCost: inscriptionCost || 0.0, // Costo de inscripción
            paymentMethods: paymentMethods || [], // Métodos de pago aceptados
            agenda: agenda || [], // Agenda del evento (lista de actividades)
            additionalInformation: additionalInformation || "", // Información adicional
            attachedDocuments: attachedDocuments || [], // Documentos adjuntos (enlaces)
            ageRestriction: ageRestriction || false, // Restricción de edad
            contactName: contactName || "", // Nombre del contacto
            contactPhone: contactPhone || "", // Teléfono de contacto
            contactEmail: contactEmail || "", // Correo electrónico de contacto
            webpage: webpage || null, // Página web oficial del evento
            instagram: instagram || null, // Instagram del evento
            facebook: facebook || null, // Facebook del evento
            youtube: youtube || null, // YouTube del evento
            linkedin: linkedin || null, // LinkedIn del evento
            createdAt: admin.firestore.FieldValue?.serverTimestamp() || new Date().toISOString(), // Marca de tiempo del evento
        };

        const eventRef = await db.collection('events').add(event);
        res.status(201).json({ id: eventRef.id, ...event });
    } catch (error) {
        console.error("Error al crear el evento:", error);
        res.status(500).json({ error: error.message });
    }
});

// Obtener eventos con paginación
app.get('/api/events', async (req, res) => {
    try {
        // Leer los parámetros de la solicitud
        const limit = parseInt(req.query.limit, 10) || 10; // Límite de eventos a obtener (por defecto 10)
        const offset = parseInt(req.query.offset, 10) || 0; // Desplazamiento (por defecto 0)

        // Consulta a Firestore con limit y offset
        const eventsRef = db.collection('events')
            .orderBy('createdAt', 'desc') // Ordenar por fecha de creación, puedes cambiarlo según tu necesidad
            .offset(offset) // Desplazar los resultados
            .limit(limit); // Límite de documentos a obtener

        const snapshot = await eventsRef.get();

        // Verificar si hay documentos
        if (snapshot.empty) {
            return res.status(200).json([]); // Retornar lista vacía si no hay eventos
        }

        // Mapear los documentos a un formato JSON
        const events = snapshot.docs.map(doc => ({
            id: doc.id, // Agregar el ID del documento
            ...doc.data() // Incluir los datos del documento
        }));

        res.status(200).json(events); // Retornar los eventos
    } catch (error) {
        console.error("Error al obtener eventos:", error);
        res.status(500).json({ error: 'Error al obtener eventos' });
    }
});

app.get('/api/events/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const eventDoc = await db.collection('events').doc(id).get();

        if (!eventDoc.exists) {
            return res.status(404).json({ message: 'Evento no encontrado' });
        }

        res.status(200).json({ id: eventDoc.id, ...eventDoc.data() });
    } catch (error) {
        console.error("Error al obtener el evento:", error) ;
        res.status(500).json({ error: 'Error al obtener el evento' });
    }
});

app.patch('/api/update-event/:id', authenticateUser, async (req, res) => {
    const { id } = req.params;
    const {
      name,
      description,
      startDate,
      endDate,
      startTime,
      endTime,
      differentSchedulesPerDay,
      location,
      headerImage,
      inscriptionStartDate,
      inscriptionEndDate,
      inscriptionStartTime,
      inscriptionEndTime,
      isPublic,
      capacity,
      inscriptionCost,
      paymentMethods,
      agenda,
      additionalInformation,
      attachedDocuments,
      ageRestriction,
      contactName,
      contactPhone,
      contactEmail,
      webpage,
      instagram,
      facebook,
      youtube,
      linkedin,
    } = req.body;
  
    if (!req.user || !req.user.uid) {
      return res.status(403).json({ message: 'Usuario no autenticado.' });
    }
  
    try {
      console.log('ID del evento:', id);
      console.log('Datos recibidos para actualizar:', req.body);
  
      // Referencia al documento
      const eventRef = db.collection('events').doc(id);
  
      // Verificar si el evento existe
      const eventDoc = await eventRef.get();
      if (!eventDoc.exists) {
        return res.status(404).json({ message: 'El evento no existe.' });
      }
  
      // Datos actuales del evento
      const currentData = eventDoc.data();
  
      // Construir el objeto actualizado con el orden original
      const updatedEvent = {
        id: id,
        createdBy: currentData.createdBy,
        name: typeof name !== 'undefined' ? name : currentData.name,
        description: typeof description !== 'undefined' ? description : currentData.description,
        startDate: typeof startDate !== 'undefined' ? startDate : currentData.startDate,
        endDate: typeof endDate !== 'undefined' ? endDate : currentData.endDate,
        startTime: typeof startTime !== 'undefined' ? startTime : currentData.startTime,
        endTime: typeof endTime !== 'undefined' ? endTime : currentData.endTime,
        differentSchedulesPerDay: typeof differentSchedulesPerDay !== 'undefined' ? differentSchedulesPerDay : currentData.differentSchedulesPerDay,
        location: typeof location !== 'undefined' ? location : currentData.location,
        headerImage: typeof headerImage !== 'undefined' ? headerImage : currentData.headerImage,
        inscriptionStartDate: typeof inscriptionStartDate !== 'undefined' ? inscriptionStartDate : currentData.inscriptionStartDate,
        inscriptionEndDate: typeof inscriptionEndDate !== 'undefined' ? inscriptionEndDate : currentData.inscriptionEndDate,
        inscriptionStartTime: typeof inscriptionStartTime !== 'undefined' ? inscriptionStartTime : currentData.inscriptionStartTime,
        inscriptionEndTime: typeof inscriptionEndTime !== 'undefined' ? inscriptionEndTime : currentData.inscriptionEndTime,
        isPublic: typeof isPublic !== 'undefined' ? isPublic : currentData.isPublic,
        capacity: typeof capacity !== 'undefined' ? capacity : currentData.capacity,
        inscriptionCost: typeof inscriptionCost !== 'undefined' ? inscriptionCost : currentData.inscriptionCost,
        paymentMethods: typeof paymentMethods !== 'undefined' ? paymentMethods : currentData.paymentMethods,
        agenda: typeof agenda !== 'undefined' ? agenda : currentData.agenda,
        additionalInformation: typeof additionalInformation !== 'undefined' ? additionalInformation : currentData.additionalInformation,
        attachedDocuments: typeof attachedDocuments !== 'undefined' ? attachedDocuments : currentData.attachedDocuments,
        ageRestriction: typeof ageRestriction !== 'undefined' ? ageRestriction : currentData.ageRestriction,
        contactName: typeof contactName !== 'undefined' ? contactName : currentData.contactName,
        contactPhone: typeof contactPhone !== 'undefined' ? contactPhone : currentData.contactPhone,
        contactEmail: typeof contactEmail !== 'undefined' ? contactEmail : currentData.contactEmail,
        webpage: typeof webpage !== 'undefined' ? webpage : currentData.webpage,
        instagram: typeof instagram !== 'undefined' ? instagram : currentData.instagram,
        facebook: typeof facebook !== 'undefined' ? facebook : currentData.facebook,
        youtube: typeof youtube !== 'undefined' ? youtube : currentData.youtube,
        linkedin: typeof linkedin !== 'undefined' ? linkedin : currentData.linkedin,
        createdAt: currentData.createdAt,
        updatedAt: new Date().toISOString(), // Usar timestamp manual
      };
  
      // Actualizar el documento
      await eventRef.update(updatedEvent);
  
      // Responder directamente con el evento actualizado
      res.status(200).json(updatedEvent);
    } catch (error) {
      console.error('Error al actualizar el evento:', error);
      res.status(500).json({
        error: error.message,
        stack: error.stack,
      });
    }
  });   

// Exporta la aplicación para Firebase Functions
exports.app = functions.https.onRequest(app);
