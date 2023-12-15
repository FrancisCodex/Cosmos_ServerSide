const pool = require('../config/database')
const dotenv = require('dotenv');
dotenv.config();


async function logAction(action, user_id, details) {
    try {
      await pool.query('INSERT INTO cosmos.audit_logs (log_action, user_id, details) VALUES ($1, $2, $3)', [action, user_id, details]);
    } catch (error) {
      console.error(error);
    }
}
//page must be accessed by the admin 

exports.getProducts = (req, res) => {
    //api call to get all the products available
    pool.query('SELECT * FROM cosmos.products', (error, results) => {
        if (error) {
            throw error
        }
        res.status(200).json(results.rows)
    })
}

exports.viewAllProducts = (req, res) => {
    //api call to get all the products available
    pool.query('SELECT * FROM cosmos.products', (error, results) => {
        if (error) {
            throw error
        }
        res.status(200).json(results.rows)
    })
}

exports.storeProduct = (req, res) => {
    //api call to store a product in the database
    const { product_name, product_description, product_price, product_image, product_category, product_quantity } = req.body

    try{
        pool.query('INSERT INTO cosmos.products (product_name, product_description, product_price, product_image, product_quantity) VALUES ($1, $2, $3, $4, $5, $6)', [product_name, product_description, product_price, product_image, product_category, product_quantity], (error, results) => {


            res.status(201).send(`Product added with ID: ${results.insertId}`)
        })
    }catch(error){
        console.log(error)
        res.send(error)
    }
}

exports.deleteProduct = (req, res) => {
    const {id} = req.params

    pool.query('DELETE FROM cosmos.products WHERE product_id = $1', [id], async (error, results) => {
        if (error) {
            throw error
        }
        await logAction('Delete Product', {id}, `Deleted product with ID: ${id}`);
        res.status(200).send(`Product deleted with ID: ${id}`)
    })
}

exports.updateProduct = (req, res) => {
    //api call to update a product in the database
    const id = parseInt(req.params.id)

    const { product_name, product_description, product_price, product_image, product_category, product_quantity } = req.body

    pool.query(
        'UPDATE cosmos.products SET product_name = $1, product_description = $2, product_price = $3, product_image = $4, product_category = $5, product_quantity = $6 WHERE product_id = $7',
        [product_name, product_description, product_price, product_image, product_category, product_quantity, id],
        async (error, results) => {
            if (error) {
                throw error
            }
            await logAction('Update Product', req.user.id, `Updated product with ID: ${id}`);
            res.status(200).send(`Product modified with ID: ${id}`)
        }
    )
}
