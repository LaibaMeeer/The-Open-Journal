import express from 'express';
import bodyParser from 'body-parser';
import env from 'dotenv';
import pg from 'pg';
import bcrypt from 'bcrypt';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import session from 'express-session';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import flash from 'connect-flash';
import ejs from 'ejs';

env.config();

const app = express();
const port = 3000;
const saltRounds = 10;
const date = new Date().toISOString().split('T')[0];

// Database setup
const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT
});
db.connect();

// Middlewares
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
}));

app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

// Multer setup
const storage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 1000000 }, // Limit file size to 1MB
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png|gif/;
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = filetypes.test(file.mimetype);

        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb('Error: Images only!');
        }
    }
}).single('image');

// Passport Local Strategy configuration
passport.use(new LocalStrategy(
  {
    usernameField: 'email', // Adjust to your form's field names
    passwordField: 'password'
  },
  async (email, password, done) => {
    try {
      const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
      const user = result.rows[0];

      if (!user) {
        return done(null, false, { message: 'Incorrect email.' });
      }

      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return done(null, false, { message: 'Incorrect password.' });
      }

      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

// Serialize and deserialize user instances to and from the session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const result = await db.query('SELECT * FROM users WHERE id = $1', [id]);
    const user = result.rows[0];
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Middleware to check authentication
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
}
function formatDate(date) {
    return new Date(date).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
}
// Routes
app.get('/', async (req, res) => {

    try{
        const posts=await db.query("SELECT * FROM posts ");
        if(posts.rows.length>0){
            res.render('index.ejs', { user: req.user ,blogs:posts.rows});
        }
        
    }
    catch(err){
        console.log(err);
    }
});
//search result
app.get('/search', async (req, res) => {
    const searchQuery = req.query.query;
  
    try {
        const result = await db.query('SELECT * FROM posts WHERE category ILIKE $1', [`%${searchQuery}%`]);
        res.json({ posts: result.rows });
    } catch (error) {
        console.error('Error fetching search results:', error);
        res.status(500).send('Server Error');
    }
  });
app.get('/category/:category', async (req, res) => {

    try{
        const posts=await db.query("SELECT * FROM posts  WHERE category=$1",[req.params.category]);
        if(posts.rows.length>0){
            res.render('chosenBlogs.ejs', { user: req.user ,blogs:posts.rows});
        }
    }
    catch(err){
        console.log(err);
    }
});
app.get('/blog/:id', async (req, res) => {
   console.log(req.params.id);
    try{ 
        const post=await db.query("SELECT * FROM posts WHERE id=$1",[req.params.id]);
        const comments = await db.query(`
            SELECT comments.comment_text, users.username
            FROM comments 
            JOIN users ON comments.user_id = users.id 
            WHERE comments.blog_id = $1
        `, [req.params.id]);        
       
        if(post.rows.length>0 || comments.rows.length){
            res.render('blog.ejs', { blog:post.rows[0],comments:comments.rows});
        }
        
    }
    catch(err){
        console.log(err);
    }
});
app.get('/login', (req, res) => {
    const messages = req.flash('error');
    res.render('login.ejs', { user: req.user, messages });
});

app.get('/register', (req, res) => {
    res.render('signup.ejs', { user: req.user });
});


app.get('/profile', ensureAuthenticated, async (req, res) => {
    try {
        const result = await db.query('SELECT * FROM users WHERE id=$1', [req.user.id]);

        // Fetch all blog posts of the current user
        const blog = await db.query('SELECT * FROM posts WHERE userId=$1', [req.user.id]);
     blog.rows = blog.rows.map(post => {
    post.date = formatDate(post.postdate); // Format the date before sending to EJS
    return post;
     });
res.render('profile.ejs', { user: result.rows[0], blog: blog.rows });

    } catch (err) {
        console.error('Error fetching user details:', err);
        res.status(500).send('Server error');
    }
});


app.get('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) {
            return next(err);
        }
        res.redirect('/');
    });
});

app.get('/postBlog', async (req, res) => {
    try {
        const category = await db.query('SELECT * FROM category');
        if (category.rows.length > 0) {
            res.render('postBlog.ejs', { category: category.rows });
        } else {
            res.status(404).send('Categories not found');
        }
    } catch (err) {
        console.error('Error fetching categories:', err);
        res.status(500).send('Server error');
    }
});
app.get('/editBlog/:id', async (req, res) => {
    console.log(req.params.id);
    try {
        const category = await db.query('SELECT * FROM category');
            
        const post = await db.query('SELECT * FROM posts WHERE id=$1',[req.params.id]);
        if (post.rows.length > 0 || category.rows.length > 0) {
            res.render('editblog.ejs', { post: post.rows[0] ,category:category.rows});
        } else {
            res.status(404).send('Post not found');
        }
    } catch (err) {
        console.error('Error fetching Post:', err);
        res.status(500).send('Server error');
    }
});
app.get("/delete/:id", async (req, res) => {
    try {
        await db.query('DELETE FROM posts WHERE id = $1', [req.params.id]);
        res.redirect("/profile");
    } catch (err) {
        console.error("Error deleting post:", err);
        res.status(500).send("Server Error");
    }
});

// POST routes
app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    try {
        const checkResult = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        if (checkResult.rows.length > 0) {
            res.redirect('/login');
        } else {
            bcrypt.hash(password, saltRounds, async (err, hash) => {
                if (err) {
                    console.error('Error hashing password:', err);
                    res.status(500).send('Server error');
                } else {
                    await db.query(
                        'INSERT INTO users (username, email, password, joining) VALUES ($1, $2, $3, $4) RETURNING *',
                        [name, email, hash, date]
                    );
                    res.redirect('/');
                }
            });
        }
    } catch (err) {
        console.error('Error registering user:', err);
        res.status(500).send('Server error');
    }
});

app.post('/login', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true,
}));

app.post('/editProfile', ensureAuthenticated, async (req, res) => {
    const { name, email } = req.body;
    try {
        await db.query('UPDATE users SET username=$1, email=$2 WHERE id=$3', [name, email, req.user.id]);
        res.redirect('/profile');
    } catch (err) {
        console.error('Error updating user details:', err);
        res.status(500).send('Server error');
    }
});

app.post('/postBlog', ensureAuthenticated, (req, res) => {
    upload(req, res, async (err) => {
        if (err) {
            res.status(400).send(err);
        } else {
            if (req.file === undefined) {
                res.status(400).send('No file selected!');
            } else {
                const { title, category, content, author } = req.body;
                const imagePath = `/uploads/${req.file.filename}`;

                try {
                    await db.query(
                        'INSERT INTO posts (title,content, image_url ,category, author,postdate,userId) VALUES ($1, $2, $3, $4, $5,$6,$7)',
                        [title, content, imagePath, category, author,date,req.user.id]
                    );
                    res.redirect('/profile');
                } catch (err) {
                    console.error('Error inserting blog post:', err);
                    res.status(500).send('Server error');
                }
            }
        }
    });
});

app.post('/submitComment/:id', ensureAuthenticated, async(req, res) => {
                console.log(req.params.id);
           
                const { comment} = req.body;

                try {
                    await db.query(
                        'INSERT INTO comments (comment_text,user_Id, blog_id) VALUES ($1, $2, $3)',
                        [comment,req.user.id,req.params.id]
                    );
                    res.redirect('/blog/' + req.params.id);
                } catch (err) {
                    console.error('Error inserting blog comment:', err);
                    res.status(500).send('Server error');
                }
            
        

});

app.post("/updatePost/:id", upload, async (req, res) => {
    try {
        const { title, author, content, category } = req.body;
        
        // Fetch the current image URL from the database in case no new image is uploaded
        const post = await db.query('SELECT image_url FROM posts WHERE id = $1', [req.params.id]);
        let imagePath = post.rows[0].image_url; // Use existing image if no new image is uploaded
  
        if (req.file) {
            // If a new file is uploaded, update the image path
            imagePath = `/uploads/${req.file.filename}`;
        }
  
        await db.query(
            "UPDATE posts SET title=$1, content=$2, image_url=$3, category=$4, author=$5, postdate=$6 WHERE id=$7",
            [title, content, imagePath, category, author, date, req.params.id]
        );
  
        res.redirect("/profile");
    } catch (err) {
        console.error("Error updating post:", err);
        res.status(500).send("Server Error");
    }
});



// Start server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
