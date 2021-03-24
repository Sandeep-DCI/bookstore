const express = require("express");
const hbs = require("express-handlebars");


const session = require("express-session");

// User router
const user = require("./routes");

const app = express();

const mongoose = require("mongoose");
mongoose.connect("mongodb://localhost:27017/auth", {
    useNewUrlParser: true,
    useCreateIndex: true,
    useUnifiedTopology: true
});

mongoose.connection.on("error", console.error);
mongoose.connection.on("open", function() {
    console.log("Database connection established...");
});


app.use(express.urlencoded({extended: true}));
app.use(session({secret: "secrets", saveUninitialized: false, resave: false}));

// Serve static resources
app.use("/public", express.static("public"));

//set hbs engine 
app.engine('hbs', hbs({extname: 'hbs', defaultLayout: null}));
app.set("views", __dirname + "/views");
app.set('view engine', 'hbs');

// Initiate API
app.use("/", user);

const port = process.env.PORT || 4000;
app.listen(port, () => {
    console.log("Connected to port " + port);
});