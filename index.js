const express = require('express')
const cors = require('cors')
const app = express()
app.use(cors())
app.use(express.json())
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');

const port = 3000

const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    database: 'zenvitae',
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body
        if (!email || !password) {
            return res.status(400).json({ error: 'email y password requeridos' })
        }

        const [rows] = await pool.promise().query('SELECT `id`, `email`, `password` FROM `usuarios` WHERE email = ?', [email]);
        if (rows.length === 0) {
            return res.status(401).json({ error: 'credenciales incorrectas' })
        }

        const user = rows[0]
        const passwordMatch = await bcrypt.compare(password, user.password)
        if (!passwordMatch) {
            return res.status(401).json({ error: 'credenciales incorrectas' })
        }

        res.json({ message: 'login exitoso' })
    } catch (error) {
        console.error('Error en login:', error.message);
        res.status(500).json({ error: 'Error en el servidor' });
    }
})

app.post('/registro', async (req, res) => {
    try {
        const { email, password } = req.body
        if (!email || !password) {
            return res.status(400).json({ error: 'email y password requeridos' })
        }
        if (password.length < 6) {
            return res.status(400).json({ error: 'password debe tener al menos 6 caracteres' })
        }

        const [rows] = await pool.promise().query('SELECT `id`, `email` FROM `usuarios` WHERE email = ?', [email]);
        if (rows.length > 0) {
            return res.status(409).json({ error: 'usuario ya registrado' })
        }

        const hashedPassword = await bcrypt.hash(password, 10)
        await pool.promise().query('INSERT INTO `usuarios` (`email`, `password`) VALUES (?, ?)', [email, hashedPassword]);
        res.json({ message: 'usuario registrado exitosamente' })
    } catch (error) {
        console.error('Error en registro:', error.message);
        res.status(500).json({ error: 'Error en el servidor' });
    }
})

app.get('/usuarios', async (req, res) => {
    try {
        const [rows] = await pool.promise().query('SELECT * FROM `usuarios`');
        res.json(rows)
    } catch (error) {
        console.error('Error en usuarios:', error.message);
        res.status(500).json({ error: 'Error en el servidor' });
    }
})




app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})