const fs = require('fs');
const jsonServer = require('json-server');
const jwt = require('jsonwebtoken');
const path = require('path');
const bcrypt = require('bcryptjs');

const middlewares = jsonServer.defaults()
const server = jsonServer.create();
const router = jsonServer.router(path.join(__dirname, 'db.json'));
const secret = JSON.parse(fs.readFileSync(path.resolve(__dirname, 'privateDB.json'), 'UTF-8')).private_key;

server.use(middlewares);

server.use(async (req, res, next) => {
    await new Promise((res) => {
        setTimeout(res, 800);
    });
    next();
});

server.use(jsonServer.bodyParser);

server.post('/login', (req, res) => {
    const {username, password} = req.body;
    const db = JSON.parse(fs.readFileSync(path.resolve(__dirname, 'db.json'), 'UTF-8'));
    const {users} = db;

    const userFromBd = users.find(
        (user) => user.username === username
    );

    if (userFromBd) {
        const passwordIsValid = bcrypt.compareSync(password, userFromBd.password);
        if (!passwordIsValid) return res.status(401).send({ auth: false, token: null, msg: 'Invalid Credentials' });
        const token = jwt.sign({ id: userFromBd._id }, secret, {
            expiresIn: 86400 // expires in 24 hours
        })
        return res.status(201).send({ token });
    }

    return res.status(400).json({ message: 'AUTH ERROR'});
});

server.post('/register', async (req, res) => {
    const hashedPassword = bcrypt.hashSync(req.body.password, 10);
    const body = {
        username: req.body.username,
        password: hashedPassword
    }
    const config = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'adminPassword': 'super-secret-key'
        },
        body: JSON.stringify(body)
    }
    try {
        const response = await fetch('http://localhost:4000/users', config);
        if (response.ok) {
            const newUser = await response.json();
            const token = jwt.sign({ id: newUser._id }, secret, {
                expiresIn: 86400 // expires in 24 hours
            })
            return res.status(201).send({ token });
        } else {
            return res.status(400).json({ message: 'REGISTER ERROR'});
        }
    } catch (error) {
        
    }
});
server.post('/users', (req,res, next) => {
    if (req.headers.adminpassword === JSON.parse(fs.readFileSync(path.resolve(__dirname, 'privateDB.json'), 'UTF-8')).admin_password) {
        next();
    } else {
        return res.status(400).json({ message: 'ACCESS DENIED'});
    }
});

server.get('/users', (req,res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token)
    return res.status(403).json({ message: 'ACCESS DENIED'});
    jwt.verify(token, secret, function (err, decoded) {
        if (err)
            return res.status(500).send({ auth: false, msg: 'Failed to authenticate token.' });
        next();
    });
})

server.use(router);

server.listen(4000, () => {
    console.log('server is running on 4000 port');
});