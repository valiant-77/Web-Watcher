const express = require('express');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const app = express();
const PORT = 3000;

/******************************************************************************
 * Serve static files (your frontend HTML, CSS, JS)
 ******************************************************************************/
// Serve static files (your frontend HTML, CSS, JS)
app.use(express.static(path.join(__dirname, '../client/src')));


/******************************************************************************
 * Connect to MongoDB
 ******************************************************************************/
// MongoDB connection
mongoose.connect('mongodb://localhost:27018/webwatcher', {
})
.then(() => console.log('Connected to MongoDB'))
.catch((err) => console.error('Failed to connect to MongoDB:', err));



/******************************************************************************
 * Middleware to parse JSON
 ******************************************************************************/
// Middleware to parse JSON and form data
app.use(express.json());





/******************************************************************************
 * Define Mongoose Schemas
 ******************************************************************************/
// User schema and model
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

// Watchlist schema and model
const watchlistSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    keywords: { type: String, required: true },
    urls: { type: String, required: true },
    email: { type: String, required: false }, 
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});


/******************************************************************************
 * Create Mongoose Models
 ******************************************************************************/
// Create the User model
const User = mongoose.model('User', userSchema);

// Create the Watchlist model
const Watchlist = mongoose.model('Watchlist', watchlistSchema);


/******************************************************************************
 * Authentication Middleware
 ******************************************************************************/
// Authentication middleware
const authenticate = (req, res, next) => {
    const authHeader = req.header('Authorization');

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    const token = authHeader.split(' ')[1];

    try {
        // Verify the token
        const decoded = jwt.verify(token, 'your-secret-key');
        req.user = decoded;
        next();
    } catch (err) {
        res.status(400).json({ error: 'Invalid token.' });
    }
};


// Email validation
function validateEmail(email) {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
}

/******************************************************************************
 * Routes
 ******************************************************************************/

/****************Route to register a new user***********************/
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Check if the username already exists
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();

        // Return success response
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to register user' });
    }
});



/**************** Route to login a user***********************/ 
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Find the user by username
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ error: 'Invalid username or password' });
        }

        // Compare the provided password with the hashed password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid username or password' });
        }

        // Generate a JWT token
        const token = jwt.sign({ _id: user._id }, 'your-secret-key', { expiresIn: '1h' });

        // Return the token
        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: 'Failed to login' });
    }
});

/****************Route to fetch user data***********************/ 
app.get('/api/user', authenticate, async (req, res) => {
    try {
        // Find the user by ID and exclude the password field
        const user = await User.findById(req.user._id).select('-password');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Return the user data
        res.json(user);
    } catch (err) {
        console.error('Error fetching user data:', err);
        res.status(500).json({ error: 'Failed to fetch user data' });
    }
});

/****************Route to save watchlist data***********************/
app.post('/api/watchlist', authenticate, async (req, res) => {
    try {
        const { keywords, urls, email } = req.body;
        const userId = req.user._id;

        if (!keywords || !urls) {
            return res.status(400).json({ error: 'Keywords and URLs are required' });
        }

        // NEW: Validate maximum items limit
        const keywordArray = keywords.split(',');
        const urlArray = urls.split('\n');

        if (keywordArray.length > 10) {
            return res.status(400).json({ error: 'Maximum 10 keywords allowed' });
        }

        if (urlArray.length > 10) {
            return res.status(400).json({ error: 'Maximum 10 URLs allowed' });
        }

        // Validate email if provided
        if (email && !validateEmail(email)) {
            return res.status(400).json({ error: 'Invalid email address format' });
        }

        // Check if the user already has a watchlist
        let watchlist = await Watchlist.findOne({ userId });

        if (watchlist) {
            // Update existing watchlist
            watchlist.keywords = keywords;
            watchlist.urls = urls;
            watchlist.email = email || watchlist.email; // Update email if provided
            watchlist.updatedAt = Date.now();
            await watchlist.save();
        } else {
            // Create new watchlist
            watchlist = new Watchlist({
                userId,
                keywords,
                urls,
                email // Save email if provided
            });
            await watchlist.save();
        }

        res.status(200).json({ 
            message: 'Saved successfully',
            watchlist,
            emailStatus: email ? 'Email saved successfully' : 'No email provided'
        });
    } catch (err) {
        console.error('Error saving watchlist:', err);
        res.status(500).json({ error: 'Failed to save watchlist' });
    }
});

/****************Route to get watchlist data***********************/
app.get('/api/watchlist', authenticate, async (req, res) => {
    try {
        const userId = req.user._id;
        
        // Find watchlist for the user
        const watchlist = await Watchlist.findOne({ userId });
        
        if (!watchlist) {
            return res.json({ keywords: '', urls: '', email: '' }); // Return empty watchlist if none exists
        }
        
        res.json(watchlist);
    } catch (err) {
        console.error('Error fetching watchlist:', err);
        res.status(500).json({ error: 'Failed to fetch watchlist' });
    }
});

/******************************************************************************
 * Start the server
 ******************************************************************************/
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});