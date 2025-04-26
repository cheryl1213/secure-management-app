// server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
require('dotenv').config();

// Import routes
const authRoutes = require('./routes/auth');
const taskRoutes = require('./routes/tasks');

// Initialize express app
const app = express();

// Middleware
app.use(express.json());
app.use(cors());
app.use(helmet()); // Security headers
app.use(morgan('dev')); // Logging

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/tasks', taskRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    message: 'Something went wrong',
    error: process.env.NODE_ENV === 'production' ? {} : err
  });
});

// Start server
const PORT = process.env.PORT || 8000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));