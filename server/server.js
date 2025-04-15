require('dotenv').config();
const express = require('express');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const axios = require('axios');
const cheerio = require('cheerio');
const cron = require('node-cron');
const nodemailer = require('nodemailer');
const app = express();
const PORT = process.env.PORT || 3000;

let lastEmailSent = null;
/******************************************************************************
 * Serve static files (your frontend HTML, CSS, JS)
 ******************************************************************************/
// Serve static files (your frontend HTML, CSS, JS)
app.use(express.static(path.join(__dirname, '../client/src')));


/******************************************************************************
 * Connect to MongoDB
 ******************************************************************************/
// MongoDB connection
const MONGODB_URI = process.env.MONGODB_URI;
mongoose.connect(MONGODB_URI)
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

// Add a new schema for storing matched results
const matchResultSchema = new mongoose.Schema({
    watchlistId: { type: mongoose.Schema.Types.ObjectId, ref: 'Watchlist', required: true },
    url: { type: String, required: true },
    matchedKeywords: [String],
    timestamp: { type: Date, default: Date.now }
});


const scanCountSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    count: { type: Number, default: 0 },
    lastReset: { type: Date, default: Date.now }
});

/******************************************************************************
 * Create Mongoose Models
 ******************************************************************************/
// Create the User model
const User = mongoose.model('User', userSchema);

// Create the Watchlist model
const Watchlist = mongoose.model('Watchlist', watchlistSchema);

// Create the MatchResult model
const MatchResult = mongoose.model('MatchResult', matchResultSchema);


// Create the ScanCount model
const ScanCount = mongoose.model('ScanCount', scanCountSchema);

/******************************************************************************
 * Authentication Middleware
 ******************************************************************************/
// Authentication middleware
const JWT_SECRET = process.env.JWT_SECRET;

const authenticate = (req, res, next) => {
    const authHeader = req.header('Authorization');

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    const token = authHeader.split(' ')[1];

    try {
        // Verify the token
        const decoded = jwt.verify(token, JWT_SECRET);
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
        const token = jwt.sign({ _id: user._id }, JWT_SECRET, { expiresIn: '1h' });

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
        const { keywords, urls, email, removeEmail } = req.body;
        const userId = req.user._id;

        if (!keywords || !urls) {
            return res.status(400).json({ error: 'Keywords and URLs are required' });
        }

        // Validate maximum items limit
        const keywordArray = keywords.split(',');
        const urlArray = urls.split('\n');

        if (keywordArray.length > 10) {
            return res.status(400).json({ error: 'Maximum 10 keywords allowed' });
        }

        if (urlArray.length > 10) {
            return res.status(400).json({ error: 'Maximum 10 URLs allowed' });
        }

        // Validate email if provided and not being removed
        if (email && !removeEmail && !validateEmail(email)) {
            return res.status(400).json({ error: 'Invalid email address format' });
        }

        // Check if the user already has a watchlist
        let watchlist = await Watchlist.findOne({ userId });

        if (watchlist) {
            // Update existing watchlist
            watchlist.keywords = keywords;
            watchlist.urls = urls;
            
            // Handle email updates
            if (removeEmail || email === '') {
                watchlist.email = null; 
            } else if (email) {
                watchlist.email = email; 
            }
           
            
            watchlist.updatedAt = Date.now();
            await watchlist.save();
        } else {
            // Create new watchlist
            watchlist = new Watchlist({
                userId,
                keywords,
                urls,
                email: removeEmail ? null : email 
            });
            await watchlist.save();
        }

        let emailStatus = null;
        if (removeEmail || email === '') {
            emailStatus = 'Email notifications disabled';
        } else if (email) {
            emailStatus = 'Email saved successfully';
        }

        res.status(200).json({ 
            message: 'Saved successfully',
            watchlist,
            emailStatus
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

/****************Route to get match results***********************/
app.get('/api/matches', authenticate, async (req, res) => {
    try {
        const userId = req.user._id;
        
        // Find watchlist for the user
        const watchlist = await Watchlist.findOne({ userId });
        
        if (!watchlist) {
            return res.json([]);
        }
        
        // Find matches for the watchlist
        const matches = await MatchResult.find({ 
            watchlistId: watchlist._id 
        }).sort({ timestamp: -1 }); // Sort by newest first
        
        res.json(matches);
    } catch (err) {
        console.error('Error fetching matches:', err);
        res.status(500).json({ error: 'Failed to fetch matches' });
    }
});

/****************Route to manually trigger a scan***********************/
app.post('/api/scan', authenticate, async (req, res) => {
    try {
        const userId = req.user._id;
        
        // Check scan limit
        let scanCount = await ScanCount.findOne({ userId });
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        // If no scan record exists or it's from a previous day, create/reset it
        if (!scanCount) {
            scanCount = new ScanCount({ userId, count: 0, lastReset: new Date() });
        } else if (scanCount.lastReset < today) {
            // Reset count if it's a new day
            scanCount.count = 0;
            scanCount.lastReset = new Date();
        }
        
        // Check if user has reached the daily limit
        if (scanCount.count >= 4) {
            return res.status(429).json({ 
                error: 'Daily scan limit reached (4/day). Next scan available tomorrow.' 
            });
        }
        
        // Increment the count
        scanCount.count += 1;
        await scanCount.save();
        
        // Find watchlist for the user
        const watchlist = await Watchlist.findOne({ userId });
        
        if (!watchlist) {
            return res.status(404).json({ error: 'No watchlist found' });
        }
        
        // Process the watchlist
        const results = await processWatchlist(watchlist);
        
        res.json({ 
            message: 'Scan completed', 
            matches: results.filter(r => r.matchedKeywords.length > 0),
            scansRemaining: 4 - scanCount.count
        });
    } catch (err) {
        console.error('Error during manual scan:', err);
        res.status(500).json({ error: 'Failed to complete scan' });
    }
});

/************Route to Check if email was sent**************/
app.get('/api/email-status', authenticate, async (req, res) => {
    if (lastEmailSent) {
        const isRecent = (Date.now() - lastEmailSent.timestamp) < 3600000;
        
        if (isRecent) {
            // Store the response
            const response = {
                emailSent: true,
                timestamp: lastEmailSent.timestamp,
                recipient: lastEmailSent.email.split('@')[0] + '@***'
            };
            
            // Clear the variable
            lastEmailSent = null;
            
            // Send the response
            return res.json(response);
        }
    }
    
    res.json({ emailSent: false });
});

/****************Route to delete a match result***********************/
app.delete('/api/matches/:id', authenticate, async (req, res) => {
    try {
        const matchId = req.params.id;
        const userId = req.user._id;
        
        // Find the watchlist for this user
        const watchlist = await Watchlist.findOne({ userId });
        
        if (!watchlist) {
            return res.status(404).json({ error: 'Watchlist not found' });
        }
        
        // Find the match and ensure it belongs to this user's watchlist
        const match = await MatchResult.findOne({ 
            _id: matchId,
            watchlistId: watchlist._id
        });
        
        if (!match) {
            return res.status(404).json({ error: 'Match result not found or not authorized' });
        }
        
        // Delete the match
        await MatchResult.deleteOne({ _id: matchId });
        
        res.json({ message: 'Match result deleted successfully' });
    } catch (err) {
        console.error('Error deleting match result:', err);
        res.status(500).json({ error: 'Failed to delete match result' });
    }
});

/****************Route to handle feedback submissions***********************/
app.post('/api/feedback', async (req, res) => {
    try {
        const { feedback, email,Name } = req.body;
        const defaultEmail = process.env.FEEDBACK_EMAIL || process.env.EMAIL_USER; // Use a dedicated feedback email or fall back to your main email
        
        if (!feedback || feedback.trim() === '') {
            return res.status(400).json({ error: 'Feedback content is required' });
        }

        // Prepare email content
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: defaultEmail,
            subject: 'WebWatcher Feedback',
            html: `
                <h2>New Feedback Received</h2>
                <p><strong>Feedback:</strong> ${feedback}</p>
                ${Name ? `<p><strong>User Name:</strong> ${Name}</p>` : '<p><strong>User Name:</strong> Not provided</p>'}
                ${email ? `<p><strong>User Email:</strong> ${email}</p>` : '<p><strong>User Email:</strong> Not provided</p>'}
                <p><strong>Timestamp:</strong> ${new Date().toLocaleString()}</p>
            `
        };
        
        // Send the email
        await transporter.sendMail(mailOptions);
        console.log('Feedback email sent successfully');
        
        res.status(200).json({ message: 'Feedback submitted successfully' });
    } catch (err) {
        console.error('Error submitting feedback:', err);
        res.status(500).json({ error: 'Failed to submit feedback' });
    }
});


// Updated server-side route to handle keyword deletion with better edge case handling
app.delete('/api/watchlist/keyword', authenticate, async (req, res) => {
    try {
        const { keyword } = req.body;
        const userId = req.user._id;
        
        // Find the user's watchlist
        const watchlist = await Watchlist.findOne({ userId });
        
        if (!watchlist) {
            return res.status(404).json({ error: 'Watchlist not found' });
        }
        
        // Get current keywords and remove the specified one
        const currentKeywords = watchlist.keywords.split(',').map(k => k.trim());
        const updatedKeywords = currentKeywords.filter(k => k !== keyword && k !== '');
        
        // Make sure we have at least one placeholder if all keywords are removed
        watchlist.keywords = updatedKeywords.length > 0 ? updatedKeywords.join(',') : 'placeholder';
        watchlist.updatedAt = Date.now();
        await watchlist.save();
        
        res.status(200).json({ 
            message: 'Keyword deleted successfully',
            watchlist
        });
    } catch (err) {
        console.error('Error deleting keyword:', err);
        res.status(500).json({ error: 'Failed to delete keyword' });
    }
});

// Updated server-side route to handle URL deletion with better edge case handling
app.delete('/api/watchlist/url', authenticate, async (req, res) => {
    try {
        const { url } = req.body;
        const userId = req.user._id;
        
        // Find the user's watchlist
        const watchlist = await Watchlist.findOne({ userId });
        
        if (!watchlist) {
            return res.status(404).json({ error: 'Watchlist not found' });
        }
        
        // Get current URLs and remove the specified one
        const currentUrls = watchlist.urls.split('\n').map(u => u.trim());
        const updatedUrls = currentUrls.filter(u => u !== url && u !== '');
        
        // Make sure we have at least one placeholder if all urls are removed
        watchlist.urls = updatedUrls.length > 0 ? updatedUrls.join('\n') : 'placeholder';
        watchlist.updatedAt = Date.now();
        await watchlist.save();
        
        res.status(200).json({ 
            message: 'URL deleted successfully',
            watchlist
        });
    } catch (err) {
        console.error('Error deleting URL:', err);
        res.status(500).json({ error: 'Failed to delete URL' });
    }
});

/******************************************************************************
 * Web Scraping Functionality
 ******************************************************************************/

// Email transporter configuration
const transporter = nodemailer.createTransport({
    service: 'gmail', // or your preferred service
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
    }
});

// Initialize web scraper
function initScraper() {
    console.log('Initializing web scraper...');
    
    // Schedule the scraper to run every 6 hours
    cron.schedule('0 */6 * * *', async () => {
        console.log('Running scheduled scraping task:', new Date().toISOString());
        try {
            await scrapeAllWatchlists();
        } catch (error) {
            console.error('Error in scheduled scraping:', error);
        }
    });
    
    console.log('Web scraper initialized and scheduled');
}

// Main function to scrape all watchlists
async function scrapeAllWatchlists() {
    // Get all watchlists from the database
    const watchlists = await Watchlist.find().populate('userId', 'username');
    console.log(`Found ${watchlists.length} watchlists to process`);
    
    // Process each watchlist
    for (const watchlist of watchlists) {
        await processWatchlist(watchlist);
    }
}

// Process a single watchlist
async function processWatchlist(watchlist) {
    const urlList = watchlist.urls.split('\n').filter(url => url.trim());
    const keywordList = watchlist.keywords.split(',').map(k => k.trim());
    
    console.log(`Processing watchlist for user ${watchlist.userId.username || watchlist.userId}`);
    console.log(`Keywords: ${keywordList.join(', ')}`);
    
    const results = [];
    
    for (const url of urlList) {
        try {
            // Skip empty URLs
            if (!url.trim()) continue;
            
            // Add http:// prefix if missing
            let processedUrl = url;
            if (!url.startsWith('http://') && !url.startsWith('https://')) {
                processedUrl = 'https://' + url;
            }
            
            const matches = await scanUrlForKeywords(processedUrl, keywordList);
            
            if (matches.length > 0) {
                console.log(`Found matches for URL ${processedUrl}: ${matches.join(', ')}`);
                
                // Create a new match result record
                const matchResult = new MatchResult({
                    watchlistId: watchlist._id,
                    url: processedUrl,
                    matchedKeywords: matches
                });
                await matchResult.save();
                
                results.push({
                    url: processedUrl,
                    matchedKeywords: matches
                });
                
                // Send email notification if email is provided
                if (watchlist.email) {
                    await sendEmailNotification(watchlist.email, processedUrl, matches);
                }
            }
        } catch (error) {
            console.error(`Error scanning URL ${url}:`, error.message);
            results.push({
                url,
                error: error.message,
                matchedKeywords: []
            });
        }
    }
    
    return results;
}

// Scan a single URL for keywords
async function scanUrlForKeywords(url, keywords) {
    console.log(`Scanning URL: ${url}`);
    
    try {
        const response = await axios.get(url, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            },
            timeout: 15000 // 15 second timeout
        });
        
        const $ = cheerio.load(response.data);
        const pageText = $('body').text().toLowerCase();
        
        // Check for each keyword in the page text
        const matches = keywords.filter(keyword => 
            pageText.includes(keyword.toLowerCase())
        );
        
        return matches;
    } catch (error) {
        console.error(`Error fetching ${url}: ${error.message}`);
        throw error;
    }
}

// Send email notification when keywords are found
async function sendEmailNotification(email, url, keywords) {
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'WebWatcher Alert: Keywords Found',
        html: `
            <h2>WebWatcher Alert</h2>
            <p>We found keywords you're watching on a website:</p>
            <p><strong>URL:</strong> <a href="${url}">${url}</a></p>
            <p><strong>Keywords Found:</strong> ${keywords.join(', ')}</p>
        `
    };
    
    try {
        await transporter.sendMail(mailOptions);
        console.log(`Notification email sent to ${email}`);
        
        // Store email sent info
        lastEmailSent = {
            timestamp: Date.now(),
            email: email,
            url: url,
            keywords: keywords
        };
        
        return true;
    } catch (error) {
        console.error('Error sending email notification:', error);
        return false;
    }
}

/******************************************************************************
 * Start the server and initialize the scraper
 ******************************************************************************/
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    // Initialize the web scraper after the server starts
    initScraper();
});