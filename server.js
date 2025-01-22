/**
 * J&K Travel Blog - Main Server File
 * This file contains the core server setup and all route handlers for the blog application.
 * Built with Express.js, SQLite, and various middleware for handling authentication and file uploads.
 */

// Import required modules
const cookieParser = require('cookie-parser')
const sanitizeHTML = require('sanitize-html')
require("dotenv").config()
const marked = require("marked")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const express = require("express")
const multer = require("multer")
const path = require("path")
const db = require("better-sqlite3")("ourApp.db")
db.pragma("journal_mode = WAL")

/**
 * Multer Configuration
 * Handles file uploads for blog post images
 * Configures storage location and file filtering
 */
const storage = multer.diskStorage({
    // Set upload destination
    destination(req, file, cb) {
        cb(null, 'public/uploads/')
    },
    // Generate unique filename
    filename(req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname))
    }
})

// Configure multer with storage and file size limits
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5000000 }, // 5MB limit
    fileFilter(req, file, cb) {
        // Only allow image files
        const filetypes = /jpeg|jpg|png|gif/
        const mimetype = filetypes.test(file.mimetype)
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase())
        if (mimetype && extname) {
            cb(null, true)
        } else {
            cb(new Error('Only image files are allowed!'))
        }
    }
})

/**
 * Database Setup
 * Uses better-sqlite3 for efficient SQLite operations
 * Creates necessary tables if they don't exist
 */
const createTables = db.transaction(() => {
    // Users table for authentication
    db.prepare(`
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username STRING NOT NULL UNIQUE,
        password STRING NOT NULL
        )`).run()

    // Add image column if it doesn't exist
    const tableInfo = db.prepare("PRAGMA table_info(posts)").all()
    if (!tableInfo.some(col => col.name === 'image')) {
        db.prepare("ALTER TABLE posts ADD COLUMN image TEXT").run()
    }

    // Posts table for blog content
    db.prepare(`
        CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        createdDate TEXT,
        title STRING NOT NULL,
        body TEXT NOT NULL,
        image TEXT,
        authorid INTEGER,
        FOREIGN KEY (authorid) REFERENCES users (id)
        )
    `).run()
})

createTables()

// Initialize Express app
const app = express()

// Configure Express middleware
app.set("view engine", "ejs")  // Set EJS as the template engine
app.use(express.urlencoded({extended: true}))  // Parse URL-encoded bodies (form data)
app.use(express.static("public"))  // Serve static files from 'public' directory
app.use(cookieParser()) // Parse cookies for authentication

/**
 * HTML Sanitization and Markdown Processing
 * Converts markdown to HTML and sanitizes output to prevent XSS
 */
app.use(function (req, res, next) {
    // Make our markdown function available
    res.locals.filterUserHTML = function(content) {
        // Convert markdown to HTML
        const markdown = marked.parse(content)
        
        // Sanitize HTML to prevent XSS
        return sanitizeHTML(markdown, {
            allowedTags: ["p", "br", "ul", "li", "lo", "strong", "bold", "i", "em", "h1", "h2", "h3", "h4", "h5", "h6"],
            allowedAttributes: {}
        })
    }

    // Initialize errors array
    res.locals.errors = []

    // Check authentication cookie
    try {
        if (req.cookies.ourSimpleApp) {
            const decoded = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET)
            req.isAuthenticated = true
            req.userid = decoded.userid
            req.username = decoded.username
            res.locals.username = decoded.username
            res.locals.userid = decoded.userid
        } else {
            req.isAuthenticated = false
        }
    } catch (err) {
        req.isAuthenticated = false
    }

    next()
})

/**
 * Login Required Middleware
 * Protects routes that require authentication
 */
function mustBeLoggedIn(req, res, next) {
    if (req.isAuthenticated) {
        next()
    } else {
        res.redirect("/")
    }
}

/**
 * Post Validation
 * Validates post creation and editing
 */
function sharedPostValidation(req) {
    const errors = []
    if (!req.body.title) {
        errors.push("You must provide a title.")
    }
    if (!req.body.body) {
        errors.push("You must provide post content.")
    }
    return errors
}

// Homepage route
app.get("/", (req, res) => {
    if (req.isAuthenticated) {
        res.redirect("/home")
    } else {
        res.render("homepage")
    }
})

// Home route
app.get("/home", (req, res) => {
    if (!req.isAuthenticated) {
        res.redirect("/")
        return
    }

    let query = "SELECT p.*, p.authorid as authorid, u.username AS author FROM posts p JOIN users u ON p.authorid = u.id"
    const params = []
    const conditions = []

    // Search by title or content
    if (req.query.search) {
        conditions.push("(p.title LIKE ? OR p.body LIKE ?)")
        params.push(`%${req.query.search}%`, `%${req.query.search}%`)
    }

    // Search by date
    if (req.query.date) {
        console.log('Search date:', req.query.date);
        // Get a sample post date for comparison
        const samplePost = db.prepare("SELECT createdDate FROM posts LIMIT 1").get();
        if (samplePost) {
            console.log('Sample post date:', samplePost.createdDate);
            console.log('Sample post date substr:', samplePost.createdDate.substring(0, 10));
        }
        
        // Use strftime to ensure consistent date formatting
        conditions.push("strftime('%Y-%m-%d', p.createdDate) = strftime('%Y-%m-%d', ?)")
        params.push(req.query.date)
    }

    // Add WHERE clause if there are conditions
    if (conditions.length > 0) {
        query += " WHERE " + conditions.join(" AND ")
    }

    query += " ORDER BY p.id DESC"
    console.log('Final query:', query);
    console.log('Query params:', params);

    const posts = db.prepare(query).all(...params)
    res.render("home", { 
        posts,
        searchQuery: req.query.search || '',
        dateQuery: req.query.date || ''
    })
})

// Create Post routes
app.get("/create-post", mustBeLoggedIn, (req, res) => {
    res.render("create-post")
})

app.post("/create-post", mustBeLoggedIn, upload.single('image'), (req, res) => {
    const errors = sharedPostValidation(req)
    if (errors.length) {
        res.render("create-post", { errors, title: req.body.title, body: req.body.body })
        return
    }

    const imagePath = req.file ? '/uploads/' + req.file.filename : null
    
    // Format the date consistently
    const now = new Date();
    const formattedDate = now.toISOString().split('T')[0] + 'T' + now.toTimeString().split(' ')[0];
    
    db.prepare("INSERT INTO posts (title, body, image, authorid, createdDate) VALUES (?, ?, ?, ?, ?)").run(
        req.body.title,
        req.body.body,
        imagePath,
        req.userid,
        formattedDate
    )
    res.redirect("/home")
})

// View Post route
app.get("/post/:id", (req, res) => {
    const post = db.prepare("SELECT p.*, u.username AS author FROM posts p JOIN users u ON p.authorid = u.id WHERE p.id = ?").get(req.params.id)
    if (!post) {
        res.render("404")
        return
    }
    res.render("view-post", { post })
})

// Edit Post routes
app.get("/post/:id/edit", mustBeLoggedIn, (req, res) => {
    const post = db.prepare("SELECT * FROM posts WHERE id = ? AND authorid = ?").get(req.params.id, req.userid)
    if (!post) {
        res.render("404")
        return
    }
    res.render("edit-post", { post, errors: [] })
})

app.post("/post/:id/edit", mustBeLoggedIn, upload.single('image'), (req, res) => {
    const post = db.prepare("SELECT * FROM posts WHERE id = ? AND authorid = ?").get(req.params.id, req.userid)
    if (!post) {
        res.render("404")
        return
    }

    const errors = sharedPostValidation(req)
    if (errors.length) {
        res.render("edit-post", { post: { ...post, ...req.body }, errors })
        return
    }

    let imagePath = post.image // Keep existing image by default
    if (req.file) {
        // If new image uploaded, update the path
        imagePath = '/uploads/' + req.file.filename
    }

    db.prepare(`
        UPDATE posts 
        SET title = ?, body = ?, image = ?
        WHERE id = ? AND authorid = ?
    `).run(req.body.title, req.body.body, imagePath, req.params.id, req.userid)

    res.redirect("/post/" + req.params.id)
})

// Delete Post route
app.post("/post/:id/delete", mustBeLoggedIn, (req, res) => {
    db.prepare("DELETE FROM posts WHERE id = ? AND authorid = ?").run(req.params.id, req.userid)
    res.redirect("/home")
})

// Handle user registration POST request
app.post("/register", (req, res) => {
    // Array to store validation errors
    const errors = [];

    // Ensure username and password are strings, set to empty string if not
    req.body.username = req.body.username?.trim() ?? ""
    req.body.password = req.body.password?.trim() ?? ""

    // Validate username
    if (req.body.username.length < 3) {
        errors.push("Username must be at least 3 characters long");
    }
    if (req.body.username.length > 20) {
        errors.push("Username cannot exceed 20 characters");
    }
    if (!req.body.username.match(/^[a-zA-Z0-9]+$/)) {
        errors.push("Username can only contain letters and numbers");
    }

    // Validate password
    if (req.body.password.length < 8) {
        errors.push("Password must be at least 8 characters long");
    }
    if (req.body.password.length > 50) {
        errors.push("Password cannot exceed 50 characters");
    }

    // Check if username already exists
    const existingUser = db.prepare("SELECT id FROM users WHERE username = ?").get(req.body.username);
    if (existingUser) {
        errors.push("That username is already taken");
    }

    // Check for validation errors and respond accordingly
    if (errors.length) {
        return res.render("homepage", { errors });
    }

    // save the new user into a database
    const salt = bcrypt.genSaltSync(10)
    req.body.password = bcrypt.hashSync(req.body.password, salt)

    const ourStatement = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    const result = ourStatement.run(req.body.username, req.body.password);

    const lookupStatement = db.prepare("SELECT * FROM users WHERE ROWID = ?")
    const ourUser = lookupStatement.get(result.lastInsertRowid)

    // log the user in by giving them a cookie
    const ourTokenValue = jwt.sign({exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, userid: ourUser.id, username: ourUser.username}, process.env.JWTSECRET)

    res.cookie("ourSimpleApp", ourTokenValue, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24
    })

    res.redirect("/home")
})

// Login route
app.post("/login", (req, res) => {
    const user = db.prepare("SELECT * FROM users WHERE username = ?").get(req.body.username)
    
    if (!user || !bcrypt.compareSync(req.body.password, user.password)) {
        res.render("homepage", { errors: ["Invalid username / password"] })
        return
    }

    const token = jwt.sign(
        { 
            exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
            userid: user.id,
            username: user.username
        },
        process.env.JWTSECRET
    )

    res.cookie("ourSimpleApp", token, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24
    })

    res.redirect("/home")
})

// Logout route
app.post("/logout", (req, res) => {
    res.clearCookie("ourSimpleApp")
    res.redirect("/")
})

// Start the server
const PORT = process.env.PORT || 3001
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`)
}).on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`Port ${PORT} is already in use. Please try a different port or close the application using this port.`)
    } else {
        console.error('Error starting server:', err)
    }
})
