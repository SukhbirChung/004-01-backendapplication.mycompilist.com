if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const localStrategy = require('passport-local');
const passportLocalMongoose = require('passport-local-mongoose');
const mongoStore = require('connect-mongo');
const AppError = require('./errorHandling/AppError');
const Collection = require('./databaseModels/collection');
const secret = process.env.SECRET || 'thisisasecret';
const db_url = process.env.REGISTERLOGIN_DB_URL;

const app = express();
const store = mongoStore.create({
    mongoUrl: db_url,
    secret: secret,
    touchAfter: 24 * 60 * 60
});
const sessionOptions = {
    store: store,
    name: 'userSessionCookie',
    secret: secret,
    secure: true,
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: true,
        /*sameSite: "none",*/
        expires: Date.now() + 1000 * 60 * 60 * 24 * 7,
        maxAge: 1000 * 60 * 60 * 24 * 7
    }
};
const UserSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true
    }
});
const corsOptions = {
    credentials: true,
    origin: ["http://localhost:3001", "http://www.localhost:3001"]
};

UserSchema.plugin(passportLocalMongoose);
const User = mongoose.model('User', UserSchema);

/*app.set("trust proxy", 1);*/
app.use(express.json());
app.use(cors(corsOptions));
app.use(session(sessionOptions));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new localStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

const connectToDB = async (req, res, next) => {
    try {
        await mongoose.connect(db_url);
        next();
    }
    catch (err) {
        next(new AppError(500, "Couldn't connect to the database."));
    }
}

const isAuthenticated = async (req, res, next) => {
    if (req.isAuthenticated()) {
        next();
    }
    else {
        return next(new AppError(401, "Couldn't authenticate user."));
    }
}

const registerUser = async (req, res, next) => {
    let { email, username, password } = req.body;
    username = username.toLowerCase();

    const newUser = new User({ email, username });

    try {
        await User.register(newUser, password);
        next();
    }
    catch (err) {
        if (err.message.includes('email:')) {
            err.message = 'There is already an account registered with this email.';
        }
        next(new AppError(500, err.message));
    }
}

const authenticateAndLogin = (req, res, next) => {
    req.body.username = (req.body.username).toLowerCase();

    passport.authenticate('local', (err, user, info) => {
        if (err) {
            return next(new AppError(500, "Couldn't authenticate the user."));
        }
        if (info) {
            return next(new AppError(500, info.message));
        }
        req.login(user, err => {
            if (err) {
                return next(new AppError(500, "Couldn't log in."));
            }
            next();
        })
    })(req, res, next);
}

const addToCollection = async (req, res, next) => {
    try {
        const user = await User.findById(req.user._id);
        const userCollection = await Collection.find({ user: user._id });
        const category = req.body.category;
        const item = req.body.item;

        if (userCollection.length === 0) {
            const newCollection = new Collection({
                user: user._id
            });

            newCollection[category].push(item);

            newCollection.save();
        } else {
            const userCategoryCollection = userCollection[0][category];

            for (let collectionItem of userCategoryCollection) {
                if (collectionItem.id === item.id) {
                    return res.status(201).send({ message: "Item already exists in your collection." });
                }
            }

            userCategoryCollection.push(item);
            userCollection[0].save();
        }

        res.send({ loggedInUserInfo: user, message: "Item successfully added to your collection." });
    }
    catch (err) {
        return next(err);
    }
}

const getUserCollection = async (req, res, next) => {
    try {
        const category = req.query.category;
        const userCollection = await Collection.find({ user: req.user._id });

        if (userCollection.length === 0) {
            res.send([]);
        }
        else {
            if (category === 'books') {
                res.send([...userCollection[0][category], ...userCollection[0]['nytbooks']]);
            }
            else {
                res.send(userCollection[0][category]);
            }
        }
    }
    catch (err) {
        return next(err);
    }
}

const removeFromCollection = async (req, res, next) => {
    const category = req.body.category;
    const id = req.body.id;

    try {
        const user = await User.findById(req.user._id);
        const userCollection = await Collection.find({ user: user._id });

        if (userCollection.length === 0) {
            next(new AppError(404, 'Item does not exist in your collection.'));
        }

        const indexToRemove = userCollection[0][category].findIndex((item) => item.id === id);

        if (indexToRemove === -1) {
            next(new AppError(404, 'Item does not exist in your collection.'));
        }

        userCollection[0][category].splice(indexToRemove, 1);
        await userCollection[0].save();
        res.send("Item successfully removed from your collection.");
    }
    catch (err) {
        return next(err);
    }
}

app.post('/', connectToDB, isAuthenticated, (req, res) => {
    res.send(req.user.username);
});

app.post('/signup', connectToDB, registerUser, authenticateAndLogin, (req, res) => {
    res.send("Account created successfully.");
});

app.post('/login', connectToDB, authenticateAndLogin, (req, res) => {
    res.send("Welcome! Logged in successfully.");
});

app.post('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) {
            return next(new AppError(500, "Couldn't log out."));
        }
        res.send('Logged out successfully.');
    })
});

app.post('/collection/addToCollection', connectToDB, isAuthenticated, addToCollection);

app.get('/collection/getUserCollection', connectToDB, isAuthenticated, getUserCollection);

app.post('/collection/removeFromCollection', connectToDB, isAuthenticated, removeFromCollection);

app.use((err, req, res, next) => {
    let { status = 400, message = "Something went wrong on the server side." } = err;
    res.status(status).send(message);
});

app.listen(3000, () => {
    console.log('Listening...');
});