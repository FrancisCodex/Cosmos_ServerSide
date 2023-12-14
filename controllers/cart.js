const pool = require('../config/database')
const dotenv = require('dotenv');
dotenv.config();


exports.getCart = (req, res) => {
    //api call to get all the cart items of the user
    const itemsCart = pool.query('SELECT * FROM cosmos.cart WHERE user_id = $1', [req.user.userId], (error, results) => {
        if (error) {
            throw error
        }
    })

    if(itemsCart.rows.length === 0){
        return res.status(404).json({ message: 'No items in cart' });
    }

    res.status(200).json(itemsCart.rows)
}   

exports.addCart = (req, res) => {
    //api call to store a product in the database
    const { product_id, order_id, quantity } = req.body

    try{
        pool.query('INSERT INTO cosmos.cart (product_id, order_id, quantity) VALUES ($1, $2, $3)', [product_id, order_id, quantity], (error, results) => {        
        res.status(201).send(`Cart added with ID: ${results.insertId}`)
})
    }catch(error){
    }

}

exports.deleteCartItem = (req, res) => {
    const id = parseInt(req.params.id)

    pool.query('DELETE FROM cosmos.cart WHERE order_item_id = $1', [id], (error, results) => {
        if (error) {
            throw error
        }
        res.status(200).send(`Cart deleted with ID: ${id}`)
    })
}



