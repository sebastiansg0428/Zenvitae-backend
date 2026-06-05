const express = require('express')
const app = express()
app.use(express.json())
const mysql = require('mysql2');

const port = 3000
// SELECT `id`, `email`, `password` FROM `usuarios` WHERE 1

const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    database: 'zenvitae',
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body
        const [rows] = await pool.promise().query('SELECT `id`, `email`, `password` FROM `usuarios` WHERE email = ? AND password = ?', [email, password]);
        if (rows.length > 0) {
            res.send('login exitoso')
        } else {
            res.send('credenciales incorrectas')
        }
    } catch (error) {
        console.error('Error en login:', error.message);
        res.status(500).send('Error en el servidor');
    }
})

app.post('/register', async (req, res) => {
    const { email, password } = req.body
    try {
        const [rows] = await pool.promise().query('SELECT `id`, `email`, `password` FROM `usuarios` WHERE email = ?', [email]);
        if (rows.length > 0) {
            res.send('usuario ya registrado')
        } else {
            await pool.promise().query('INSERT INTO `usuarios` (`email`, `password`) VALUES (?, ?)', [email, password]);
            res.send('usuario registrado exitosamente')
        }
    } catch (error) {
        console.error('Error en registro:', error.message);
        res.status(500).send('Error en el servidor');
    }
})

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})