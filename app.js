const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const port = 5000;

app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI);
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));

// User schema
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  email: { type: String, unique: true, required: true },
});

const User = mongoose.model('User', userSchema);

// Middleware d'erreur global
app.use((err, req, res, next) => {
    console.error(err.stack);
  
    // Envoyer une réponse d'erreur au client
    res.status(500).json({ error: 'Internal Server Error' });
  });

// Middleware de validation des entrées utilisateur
function validateUserInput(req, res, next) {
  const { username, password, email } = req.body;

  // Vérification de la présence des champs
  if (!username || !password || !email) {
    console.log('Champ manquant');
    return res.status(400).json({ error: 'Veuillez fournir un nom d\'utilisateur, un mot de passe et une adresse e-mail.' });
  }

  // Vérification du format de l'email
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    console.log('Format email incorrect');
    return res.status(400).json({ error: 'Veuillez fournir une adresse e-mail valide.' });
  }

  // Vérification de la taille du mot de passe
  if (password.length < 8) {
    console.log('Mot de passe trop court');
    return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 8 caractères.' });
  }

  next();
}


// Register route
app.post('/register', validateUserInput, async (req, res, next) => {
  try {
    const { username, password, email } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ username, password: hashedPassword, email });
    await newUser.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error(error);
    next(error);
  }
});

// Login route
app.post('/login', async (req, res, next) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Generate JWT token
    const token = jwt.sign({ username: user.username }, process.env.SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    console.error(error);
    next(error);
  }
});

// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
  console.log('Middleware authenticateToken appelé');

  const token = req.headers['authorization'];

  console.log('Token extrait:', token);

  if (!token) {
    console.log('Token absent');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
    if (err) {
      console.error('erreur de vérification du token', err);
      return res.status(403).json({ error: 'Forbidden' });
    }

    req.user = user;
    next();
  });
}

// Users route (protected with JWT)
app.post('/users', authenticateToken, async (req, res, next) => {
    try {
      const users = await User.find();
      res.json(users);
    } catch (error) {
      console.error(error);
      next(error);
    }
  });

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});