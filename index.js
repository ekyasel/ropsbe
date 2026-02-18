import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import swaggerUi from 'swagger-ui-express';
import swaggerJsdoc from 'swagger-jsdoc';
import { supabase } from './supabase.js';

const app = express();
const port = process.env.PORT || 3001;

// Swagger Configuration
const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'Ruang Operasi Proto API',
            version: '1.0.0',
            description: 'API documentation for the Express.js project with Supabase authentication',
        },
        servers: [
            {
                url: process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : `http://localhost:${port}`,
                description: process.env.VERCEL_URL ? 'Production Server' : 'Local Development Server'
            },
        ],
    },
    apis: ['./index.js'], // Path to the API docs
    components: {
        securitySchemes: {
            bearerAuth: {
                type: 'http',
                scheme: 'bearer',
                bearerFormat: 'JWT',
            },
        },
    },
    security: [
        {
            bearerAuth: [],
        },
    ],
};

// Basic middleware for parsing JSON
app.use(express.json());

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret');
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ error: 'Invalid or expired token.' });
    }
};

const swaggerDocs = swaggerJsdoc(swaggerOptions);

// Vercel compatible Swagger UI setup - Using single strings for better compatibility
const swaggerUiOptions = {
    customCss: '.swagger-ui .topbar { display: none }',
    customJs: 'https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/4.15.5/swagger-ui-bundle.js',
    customCssUrl: 'https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/4.15.5/swagger-ui.min.css'
};

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs, swaggerUiOptions));

/**
 * @openapi
 * /:
 *   get:
 *     summary: Welcome message
 *     responses:
 *       200:
 *         description: Returns a welcome message.
 */
// Hello World route
app.get('/', (req, res) => {
    res.json({ message: 'Hello World from Express!' });
});

/**
 * @openapi
 * /api/register:
 *   post:
 *     summary: Register a new user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *               full_name:
 *                 type: string
 *     responses:
 *       201:
 *         description: User registered successfully.
 *       400:
 *         description: Email already registered or missing fields.
 */
// Register API
app.post('/api/register', async (req, res) => {
    const { email, password, full_name } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        // Hash password
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        // Insert user into Supabase
        const { data, error } = await supabase
            .from('users')
            .insert([
                {
                    email,
                    password_hash: passwordHash,
                    full_name,
                    is_active: true,
                    is_admin: false
                }
            ])
            .select('id, email, full_name, created_at')
            .single();

        if (error) {
            if (error.code === '23505') { // Unique constraint violation
                return res.status(400).json({ error: 'Email already registered' });
            }
            throw error;
        }

        res.status(201).json({ message: 'User registered successfully', user: data });
    } catch (err) {
        console.error('Registration error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

/**
 * @openapi
 * /api/login:
 *   post:
 *     summary: Login a user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login successful.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                 user:
 *                   type: object
 *                 token:
 *                   type: string
 *       401:
 *         description: Invalid email or password.
 *       403:
 *         description: Account is deactivated.
 */
// Login API
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        // Fetch user from Supabase
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();

        if (error || !user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        if (!user.is_active) {
            return res.status(403).json({ error: 'Account is deactivated' });
        }

        // Compare password
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Generate JWT
        const token = jwt.sign(
            { id: user.id, email: user.email },
            process.env.JWT_SECRET || 'fallback_secret',
            { expiresIn: '24h' }
        );

        // Return user info (omit password_hash) and token
        const { password_hash, ...userInfo } = user;
        res.json({
            message: 'Login successful',
            user: userInfo,
            token: token
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

/**
 * @openapi
 * /api/users:
 *   get:
 *     summary: Get all users
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of all users.
 *       401:
 *         description: Unauthorized.
 */
// Get All Users API
app.get('/api/users', authenticateToken, async (req, res) => {
    try {
        const { data: users, error } = await supabase
            .from('users')
            .select('id, email, full_name, role, is_active, is_admin, created_at')
            .order('created_at', { ascending: false });

        if (error) throw error;
        res.json(users);
    } catch (err) {
        console.error('Fetch users error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

/**
 * @openapi
 * /api/users:
 *   post:
 *     summary: Add a new user
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *               - full_name
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *               full_name:
 *                 type: string
 *               is_admin:
 *                 type: boolean
 *               role:
 *                 type: string
 *                 default: Admin
 *     responses:
 *       201:
 *         description: User created successfully.
 *       400:
 *         description: Email already registered.
 */
// Add User API
app.post('/api/users', authenticateToken, async (req, res) => {
    const { email, password, full_name, is_admin, role } = req.body;

    if (!email || !password || !full_name) {
        return res.status(400).json({ error: 'Email, password, and full name are required' });
    }

    try {
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        const { data, error } = await supabase
            .from('users')
            .insert([
                {
                    email,
                    password_hash: passwordHash,
                    full_name,
                    is_active: true,
                    is_admin: is_admin || false,
                    role: role || 'Admin'
                }
            ])
            .select('id, email, full_name, is_active, is_admin, role, created_at')
            .single();

        if (error) {
            if (error.code === '23505') {
                return res.status(400).json({ error: 'Email already registered' });
            }
            throw error;
        }

        res.status(201).json({ message: 'User created successfully', user: data });
    } catch (err) {
        console.error('Create user error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

/**
 * @openapi
 * /api/users/{id}:
 *   put:
 *     summary: Update a user
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               full_name:
 *                 type: string
 *               is_active:
 *                 type: boolean
 *               is_admin:
 *                 type: boolean
 *               role:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: User updated successfully.
 *       404:
 *         description: User not found.
 */
// Update User API
app.put('/api/users/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { email, full_name, is_active, is_admin, role, password } = req.body;

    const updateData = {};
    if (email) updateData.email = email;
    if (full_name) updateData.full_name = full_name;
    if (is_active !== undefined) updateData.is_active = is_active;
    if (is_admin !== undefined) updateData.is_admin = is_admin;
    if (role) updateData.role = role;

    try {
        if (password) {
            const salt = await bcrypt.genSalt(10);
            updateData.password_hash = await bcrypt.hash(password, salt);
        }

        const { data, error } = await supabase
            .from('users')
            .update(updateData)
            .eq('id', id)
            .select('id, email, full_name, is_active, is_admin, role, created_at')
            .single();

        if (error) throw error;
        if (!data) return res.status(404).json({ error: 'User not found' });

        res.json({ message: 'User updated successfully', user: data });
    } catch (err) {
        console.error('Update user error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

/**
 * @openapi
 * /api/parameters:
 *   get:
 *     summary: Get all parameters
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of all parameters.
 */
// Get All Parameters API
app.get('/api/parameters', authenticateToken, async (req, res) => {
    try {
        const { data: parameters, error } = await supabase
            .from('mst_parameter')
            .select('*')
            .order('param_type', { ascending: true })
            .order('sort_order', { ascending: true });

        if (error) throw error;
        res.json(parameters);
    } catch (err) {
        console.error('Fetch parameters error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

/**
 * @openapi
 * /api/parameters/{id}:
 *   get:
 *     summary: Get a parameter by ID
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Parameter details.
 *       404:
 *         description: Parameter not found.
 */
// Get Parameter By ID API
app.get('/api/parameters/:id', authenticateToken, async (req, res) => {
    try {
        const { data: parameter, error } = await supabase
            .from('mst_parameter')
            .select('*')
            .eq('id', req.params.id)
            .single();

        if (error) throw error;
        if (!parameter) return res.status(404).json({ error: 'Parameter not found' });
        res.json(parameter);
    } catch (err) {
        console.error('Fetch parameter error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

/**
 * @openapi
 * /api/parameters:
 *   post:
 *     summary: Add a new parameter
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - param_type
 *               - param_code
 *               - param_name
 *             properties:
 *               param_type:
 *                 type: string
 *               param_code:
 *                 type: string
 *               param_name:
 *                 type: string
 *               param_value:
 *                 type: string
 *               description:
 *                 type: string
 *               sort_order:
 *                 type: integer
 *               is_active:
 *                 type: boolean
 *     responses:
 *       201:
 *         description: Parameter created successfully.
 */
// Add Parameter API
app.post('/api/parameters', authenticateToken, async (req, res) => {
    const { param_type, param_code, param_name, param_value, description, sort_order, is_active } = req.body;

    if (!param_type || !param_code || !param_name) {
        return res.status(400).json({ error: 'param_type, param_code, and param_name are required' });
    }

    try {
        const { data, error } = await supabase
            .from('mst_parameter')
            .insert([
                {
                    param_type,
                    param_code,
                    param_name,
                    param_value,
                    description,
                    sort_order: sort_order || 0,
                    is_active: is_active !== undefined ? is_active : true,
                    created_by: req.user.id
                }
            ])
            .select()
            .single();

        if (error) throw error;
        res.status(201).json({ message: 'Parameter created successfully', data });
    } catch (err) {
        console.error('Create parameter error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

/**
 * @openapi
 * /api/parameters/{id}:
 *   put:
 *     summary: Update a parameter
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               param_type:
 *                 type: string
 *               param_code:
 *                 type: string
 *               param_name:
 *                 type: string
 *               param_value:
 *                 type: string
 *               description:
 *                 type: string
 *               sort_order:
 *                 type: integer
 *               is_active:
 *                 type: boolean
 *     responses:
 *       200:
 *         description: Parameter updated successfully.
 *       404:
 *         description: Parameter not found.
 */
// Update Parameter API
app.put('/api/parameters/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const body = req.body;

    const updateData = {
        ...body,
        updated_at: new Date().toISOString(),
        updated_by: req.user.id
    };

    try {
        const { data, error } = await supabase
            .from('mst_parameter')
            .update(updateData)
            .eq('id', id)
            .select()
            .single();

        if (error) throw error;
        if (!data) return res.status(404).json({ error: 'Parameter not found' });

        res.json({ message: 'Parameter updated successfully', data });
    } catch (err) {
        console.error('Update parameter error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

/**
 * @openapi
 * /api/parameters/{id}:
 *   delete:
 *     summary: Delete a parameter
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Parameter deleted successfully.
 *       404:
 *         description: Parameter not found.
 */
// Delete Parameter API
app.delete('/api/parameters/:id', authenticateToken, async (req, res) => {
    try {
        const { error, count } = await supabase
            .from('mst_parameter')
            .delete({ count: 'exact' })
            .eq('id', req.params.id);

        if (error) throw error;
        if (count === 0) return res.status(404).json({ error: 'Parameter not found' });

        res.json({ message: 'Parameter deleted successfully' });
    } catch (err) {
        console.error('Delete parameter error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

/**
 * @openapi
 * /api/registrations:
 *   get:
 *     summary: Get surgery registrations with filtering and pagination
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: startDate
 *         description: Start date filter for planned surgery (YYYY-MM-DD)
 *         schema:
 *           type: string
 *           format: date
 *       - in: query
 *         name: endDate
 *         description: End date filter for planned surgery (YYYY-MM-DD)
 *         schema:
 *           type: string
 *           format: date
 *       - in: query
 *         name: page
 *         description: Page number
 *         schema:
 *           type: integer
 *           default: 1
 *       - in: query
 *         name: pageSize
 *         description: Number of items per page
 *         schema:
 *           type: integer
 *           default: 10
 *     responses:
 *       200:
 *         description: List of surgery registrations with pagination metadata.
 */
// Get All Registrations API (with search and paging)
app.get('/api/registrations', authenticateToken, async (req, res) => {
    try {
        const { startDate, endDate, page = 1, pageSize = 10 } = req.query;
        const pageNum = parseInt(page);
        const sizeNum = parseInt(pageSize);
        const from = (pageNum - 1) * sizeNum;
        const to = from + sizeNum - 1;

        let query = supabase
            .from('pendaftaran_operasi')
            .select('*', { count: 'exact' });

        // Add date filters if provided (filtering on planned surgery date)
        if (startDate) {
            query = query.gte('tanggal_rencana_operasi', startDate);
        }
        if (endDate) {
            query = query.lte('tanggal_rencana_operasi', endDate);
        }

        const { data: registrations, error, count } = await query
            .order('created_at', { ascending: false })
            .range(from, to);

        if (error) throw error;

        res.json({
            data: registrations,
            pagination: {
                total: count,
                page: pageNum,
                pageSize: sizeNum,
                totalPages: Math.ceil(count / sizeNum)
            }
        });
    } catch (err) {
        console.error('Fetch registrations error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

/**
 * @openapi
 * /api/registrations/{id}:
 *   get:
 *     summary: Get a surgery registration by ID
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Surgery registration details.
 *       404:
 *         description: Registration not found.
 */
// Get Registration By ID API
app.get('/api/registrations/:id', authenticateToken, async (req, res) => {
    try {
        const { data: registration, error } = await supabase
            .from('pendaftaran_operasi')
            .select('*')
            .eq('id', req.params.id)
            .single();

        if (error) throw error;
        if (!registration) return res.status(404).json({ error: 'Registration not found' });
        res.json(registration);
    } catch (err) {
        console.error('Fetch registration error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

/**
 * @openapi
 * /api/registrations:
 *   post:
 *     summary: Add a new surgery registration
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - waktu_pendaftaran
 *               - nama_pasien
 *               - no_rekam_medis
 *             properties:
 *               waktu_pendaftaran:
 *                 type: string
 *                 format: date-time
 *               pendaftaran_dari:
 *                 type: string
 *               ruangan_rawat_inap:
 *                 type: string
 *               jenis_operasi:
 *                 type: string
 *               tanggal_rencana_operasi:
 *                 type: string
 *                 format: date
 *               jam_rencana_operasi:
 *                 type: string
 *                 format: time
 *                 example: "08:00"
 *               nama_pasien:
 *                 type: string
 *               no_rekam_medis:
 *                 type: string
 *               umur_tahun:
 *                 type: string
 *               jenis_kelamin:
 *                 type: string
 *               nomor_telp_1:
 *                 type: string
 *               nomor_telp_2:
 *                 type: string
 *               diagnosis:
 *                 type: string
 *               rencana_tindakan:
 *                 type: string
 *               dokter_operator:
 *                 type: string
 *               penjamin:
 *                 type: string
 *               kelas:
 *                 type: string
 *     responses:
 *       201:
 *         description: Surgery registration created successfully.
 */
// Add Registration API
app.post('/api/registrations', authenticateToken, async (req, res) => {
    const body = req.body;

    if (!body.waktu_pendaftaran || !body.nama_pasien || !body.no_rekam_medis) {
        return res.status(400).json({ error: 'waktu_pendaftaran, nama_pasien, and no_rekam_medis are required' });
    }

    try {
        const { data, error } = await supabase
            .from('pendaftaran_operasi')
            .insert([
                {
                    ...body,
                    created_by: req.user.id,
                    created_on: new Date().toISOString()
                }
            ])
            .select()
            .single();

        if (error) throw error;
        res.status(201).json({ message: 'Registration created successfully', data });
    } catch (err) {
        console.error('Create registration error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

/**
 * @openapi
 * /api/registrations/{id}:
 *   put:
 *     summary: Update a surgery registration
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               waktu_pendaftaran:
 *                 type: string
 *                 format: date-time
 *               pendaftaran_dari:
 *                 type: string
 *               ruangan_rawat_inap:
 *                 type: string
 *               jenis_operasi:
 *                 type: string
 *               tanggal_rencana_operasi:
 *                 type: string
 *                 format: date
 *               jam_rencana_operasi:
 *                 type: string
 *                 format: time
 *                 example: "08:00"
 *               nama_pasien:
 *                 type: string
 *               no_rekam_medis:
 *                 type: string
 *               umur_tahun:
 *                 type: string
 *               jenis_kelamin:
 *                 type: string
 *               nomor_telp_1:
 *                 type: string
 *               nomor_telp_2:
 *                 type: string
 *               diagnosis:
 *                 type: string
 *               rencana_tindakan:
 *                 type: string
 *               dokter_operator:
 *                 type: string
 *               penjamin:
 *                 type: string
 *               kelas:
 *                 type: string
 *     responses:
 *       200:
 *         description: Surgery registration updated successfully.
 *       404:
 *         description: Registration not found.
 */
// Update Registration API
app.put('/api/registrations/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const body = req.body;

    const updateData = {
        ...body,
        updated_on: new Date().toISOString(),
        updated_by: req.user.id
    };

    try {
        const { data, error } = await supabase
            .from('pendaftaran_operasi')
            .update(updateData)
            .eq('id', id)
            .select()
            .single();

        if (error) throw error;
        if (!data) return res.status(404).json({ error: 'Registration not found' });

        res.json({ message: 'Registration updated successfully', data });
    } catch (err) {
        console.error('Update registration error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

/**
 * @openapi
 * /api/registrations/{id}:
 *   delete:
 *     summary: Delete a surgery registration
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Surgery registration deleted successfully.
 *       404:
 *         description: Registration not found.
 */
// Delete Registration API
app.delete('/api/registrations/:id', authenticateToken, async (req, res) => {
    try {
        const { error, count } = await supabase
            .from('pendaftaran_operasi')
            .delete({ count: 'exact' })
            .eq('id', req.params.id);

        if (error) throw error;
        if (count === 0) return res.status(404).json({ error: 'Registration not found' });

        res.json({ message: 'Registration deleted successfully' });
    } catch (err) {
        console.error('Delete registration error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
/**
 * @openapi
 * /api/report/yearly-summary-penjamin:
 *   get:
 *     summary: Get yearly monthly summary report for penjamin
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: year
 *         description: Year for the report (YYYY)
 *         required: true
 *         schema:
 *           type: integer
 *           default: 2026
 *     responses:
 *       200:
 *         description: Monthly summary pivoted by penjamin.
 */
// Yearly Monthly Summary Report API
app.get('/api/report/yearly-summary-penjamin', authenticateToken, async (req, res) => {
    const { year } = req.query;
    const reportYear = parseInt(year) || new Date().getFullYear();

    const INDONESIAN_MONTHS = [
        "JANUARI", "PEBRUARI", "MARET", "APRIL", "MEI", "JUNI",
        "JULI", "AGUSTUS", "SEPTEMBER", "OKTOBER", "NOPEMBER", "DESEMBER"
    ];


    try {
        // 1. Get all penjamin names from mst_parameter
        const { data: listPenjaminData, error: pError } = await supabase
            .from('mst_parameter')
            .select('param_name')
            .eq('param_type', 'PENJAMIN')
            .eq('is_active', true)
            .order('sort_order', { ascending: true });

        if (pError) throw pError;
        const listPenjamin = listPenjaminData.map(row => row.param_name);

        if (listPenjamin.length === 0) {
            return res.json([]);
        }

        // 2. Fetch registrations for the requested year
        const startOfYear = `${reportYear}-01-01`;
        const endOfYear = `${reportYear}-12-31`;

        const { data: dbData, error: rError } = await supabase
            .from('pendaftaran_operasi')
            .select('tanggal_rencana_operasi, penjamin')
            .gte('tanggal_rencana_operasi', startOfYear)
            .lte('tanggal_rencana_operasi', endOfYear);

        if (rError) throw rError;

        // 3. Process and Pivot logic in JS
        const report = INDONESIAN_MONTHS.map((monthName, index) => {
            const monthNum = index + 1; // 1-indexed
            const row = { "BULAN": monthName };

            // Initialize all penjamin columns with 0
            listPenjamin.forEach(p => {
                row[p] = 0;
            });

            // Aggregate from dbData
            if (dbData) {
                dbData.forEach(d => {
                    const date = new Date(d.tanggal_rencana_operasi);
                    const dMonth = date.getMonth() + 1; // 1-indexed
                    if (dMonth === monthNum && row.hasOwnProperty(d.penjamin)) {
                        row[d.penjamin]++;
                    }
                });
            }

            return row;
        });

        // 4. Add TOTAL row
        const totalRow = { "BULAN": "TOTAL" };
        listPenjamin.forEach(p => {
            totalRow[p] = report.reduce((sum, monthRow) => sum + (monthRow[p] || 0), 0);
        });
        report.push(totalRow);

        res.json(report);
    } catch (err) {
        console.error('Yearly summary report error:', err);
        res.status(500).json({
            error: 'Internal server error while generating report',
            details: err.message
        });
    }
});

/**
 * @openapi
 * /api/report/yearly-summary-poli:
 *   get:
 *     summary: Get yearly monthly summary report for a specific poli
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: year
 *         description: Year for the report (YYYY)
 *         required: false
 *         schema:
 *           type: integer
 *           default: 2026
 *       - in: query
 *         name: poli
 *         description: Poli name (pendaftaran_dari)
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Monthly summary with ELEKTIF and CITO counts.
 */
// Yearly Poli Summary Report API
app.get('/api/report/yearly-summary-poli', authenticateToken, async (req, res) => {
    const { year, poli, mock } = req.query;
    const reportYear = parseInt(year) || new Date().getFullYear();

    if (!poli && mock !== 'true') {
        return res.status(400).json({ error: 'Parameter "poli" is required' });
    }

    const INDONESIAN_MONTHS = [
        "JANUARI", "PEBRUARI", "MARET", "APRIL", "MEI", "JUNI",
        "JULI", "AGUSTUS", "SEPTEMBER", "OKTOBER", "NOPEMBER", "DESEMBER"
    ];

    // Mock response for testing
    if (mock === 'true') {
        const mockReport = INDONESIAN_MONTHS.map(month => ({
            "BULAN": month,
            "ELEKTIF": Math.floor(Math.random() * 50),
            "CITO": Math.floor(Math.random() * 20),
            "JUMLAH": 0
        }));
        mockReport.forEach(row => row.JUMLAH = row.ELEKTIF + row.CITO);

        const totalRow = {
            "BULAN": "TOTAL",
            "ELEKTIF": mockReport.reduce((s, r) => s + r.ELEKTIF, 0),
            "CITO": mockReport.reduce((s, r) => s + r.CITO, 0),
            "JUMLAH": 0
        };
        totalRow.JUMLAH = totalRow.ELEKTIF + totalRow.CITO;
        mockReport.push(totalRow);
        return res.json(mockReport);
    }

    try {
        const startOfYear = `${reportYear}-01-01`;
        const endOfYear = `${reportYear}-12-31`;

        const { data: dbData, error } = await supabase
            .from('pendaftaran_operasi')
            .select('tanggal_rencana_operasi, jenis_operasi')
            .eq('pendaftaran_dari', poli)
            .gte('tanggal_rencana_operasi', startOfYear)
            .lte('tanggal_rencana_operasi', endOfYear);

        if (error) throw error;

        const report = INDONESIAN_MONTHS.map((monthName, index) => {
            const monthNum = index + 1;
            const row = {
                "BULAN": monthName,
                "ELEKTIF": 0,
                "CITO": 0,
                "JUMLAH": 0
            };

            if (dbData) {
                dbData.forEach(d => {
                    const date = new Date(d.tanggal_rencana_operasi);
                    const dMonth = date.getMonth() + 1;
                    if (dMonth === monthNum) {
                        if (d.jenis_operasi === 'ELEKTIF') row.ELEKTIF++;
                        else if (d.jenis_operasi === 'CITO') row.CITO++;
                    }
                });
            }
            row.JUMLAH = row.ELEKTIF + row.CITO;
            return row;
        });

        const totalRow = {
            "BULAN": "TOTAL",
            "ELEKTIF": report.reduce((s, r) => s + r.ELEKTIF, 0),
            "CITO": report.reduce((s, r) => s + r.CITO, 0),
            "JUMLAH": 0
        };
        totalRow.JUMLAH = totalRow.ELEKTIF + totalRow.CITO;
        report.push(totalRow);

        res.json(report);
    } catch (err) {
        console.error('Poli summary report error:', err);
        res.status(500).json({
            error: 'Internal server error while generating poli report',
            details: err.message
        });
    }
});

/**
 * @openapi
 * /api/report/yearly-summary:
 *   get:
 *     summary: Get general yearly monthly summary report for all poli
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: year
 *         description: Year for the report (YYYY)
 *         required: false
 *         schema:
 *           type: integer
 *           default: 2026
 *     responses:
 *       200:
 *         description: Monthly summary with aggregated ELEKTIF and CITO counts across all polis.
 */
// General Yearly Summary Report API
app.get('/api/report/yearly-summary', authenticateToken, async (req, res) => {
    const { year } = req.query;
    const reportYear = parseInt(year) || new Date().getFullYear();

    const INDONESIAN_MONTHS = [
        "JANUARI", "PEBRUARI", "MARET", "APRIL", "MEI", "JUNI",
        "JULI", "AGUSTUS", "SEPTEMBER", "OKTOBER", "NOPEMBER", "DESEMBER"
    ];

    try {
        const startOfYear = `${reportYear}-01-01`;
        const endOfYear = `${reportYear}-12-31`;

        const { data: dbData, error } = await supabase
            .from('pendaftaran_operasi')
            .select('tanggal_rencana_operasi, jenis_operasi')
            .gte('tanggal_rencana_operasi', startOfYear)
            .lte('tanggal_rencana_operasi', endOfYear);

        if (error) throw error;

        const report = INDONESIAN_MONTHS.map((monthName, index) => {
            const monthNum = index + 1;
            const row = {
                "BULAN": monthName,
                "ELEKTIF": 0,
                "CITO": 0
            };

            if (dbData) {
                dbData.forEach(d => {
                    const date = new Date(d.tanggal_rencana_operasi);
                    const dMonth = date.getMonth() + 1;
                    if (dMonth === monthNum) {
                        if (d.jenis_operasi === 'ELEKTIF') row.ELEKTIF++;
                        else if (d.jenis_operasi === 'CITO') row.CITO++;
                    }
                });
            }
            return row;
        });

        const totalRow = {
            "BULAN": "TOTAL",
            "ELEKTIF": report.reduce((s, r) => s + r.ELEKTIF, 0),
            "CITO": report.reduce((s, r) => s + r.CITO, 0)
        };
        report.push(totalRow);

        res.json(report);
    } catch (err) {
        console.error('General yearly summary report error:', err);
        res.status(500).json({
            error: 'Internal server error while generating summary report',
            details: err.message
        });
    }
});

// Export the app for Vercel
export default app;

// Start the server only if we're not on Vercel
if (!process.env.VERCEL) {
    app.listen(port, () => {
        console.log(`🚀 Server ready at http://localhost:${port}`);
        console.log(`📖 Swagger docs at http://localhost:${port}/api-docs`);
    });
}

