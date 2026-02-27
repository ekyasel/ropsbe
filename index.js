import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import swaggerUi from 'swagger-ui-express';
import swaggerJsdoc from 'swagger-jsdoc';
import { supabase } from './supabase.js';
import cron from 'node-cron';

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
 * /api/test-supabase:
 *   get:
 *     summary: Test connection to Supabase (Unauthenticated)
 *     responses:
 *       200:
 *         description: Connection status and a small sample of data or error.
 */
app.get('/api/test-supabase', async (req, res) => {
    try {
        // Try to fetch a single parameter to check connectivity
        const { data, error } = await supabase
            .from('mst_parameter')
            .select('param_name')
            .limit(1);

        if (error) throw error;

        res.json({
            success: true,
            message: 'Successfully connected to Supabase',
            sampleData: data
        });
    } catch (err) {
        console.error('Supabase connection test error:', err);
        res.status(500).json({
            success: false,
            message: 'Failed to connect to Supabase',
            error: err.message
        });
    }
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
            { id: user.id, email: user.email, full_name: user.full_name, role: user.role },
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
            .select('*, user_created:created_by(full_name)', { count: 'exact' });

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

        // Flatten user_created nested object to string
        const flattenedRegistrations = registrations?.map(reg => ({
            ...reg,
            user_created: reg.user_created?.full_name || null
        }));

        res.json({
            data: flattenedRegistrations,
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
 *               dokter_anestesi:
 *                 type: string
 *               penjamin:
 *                 type: string
 *               kelas:
 *                 type: string
 *               klasifikasi_operasi:
 *                 type: string
 *               catatan:
 *                 type: string
 *               ruang_operasi:
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
 *               dokter_anestesi:
 *                 type: string
 *               penjamin:
 *                 type: string
 *               kelas:
 *                 type: string
 *               klasifikasi_operasi:
 *                 type: string
 *               catatan:
 *                 type: string
 *               ruang_operasi:
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
                "KHUSUS": 0,
                "BESAR": 0,
                "SEDANG": 0,
                "KECIL": 0,
                "JUMLAH": 0
            };

            if (dbData) {
                dbData.forEach(d => {
                    const date = new Date(d.tanggal_rencana_operasi);
                    const dMonth = date.getMonth() + 1;
                    if (dMonth === monthNum) {
                        // Count Jenis Operasi
                        if (d.jenis_operasi === 'ELEKTIF') row.ELEKTIF++;
                        else if (d.jenis_operasi === 'CITO') row.CITO++;

                        // Count Klasifikasi Operasi
                        const klasifikasi = d.klasifikasi_operasi ? d.klasifikasi_operasi.toUpperCase() : null;
                        if (klasifikasi) {
                            if (row[klasifikasi] !== undefined) {
                                row[klasifikasi]++;
                            } else {
                                row[klasifikasi] = 1;
                            }
                        }
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
                "CITO": 0,
                "KHUSUS": 0,
                "BESAR": 0,
                "SEDANG": 0,
                "KECIL": 0
            };

            if (dbData) {
                dbData.forEach(d => {
                    const date = new Date(d.tanggal_rencana_operasi);
                    const dMonth = date.getMonth() + 1;
                    if (dMonth === monthNum) {
                        // Count Jenis Operasi
                        if (d.jenis_operasi === 'ELEKTIF') row.ELEKTIF++;
                        else if (d.jenis_operasi === 'CITO') row.CITO++;

                        // Count Klasifikasi Operasi
                        const klasifikasi = d.klasifikasi_operasi ? d.klasifikasi_operasi.toUpperCase() : null;
                        if (klasifikasi) {
                            if (row[klasifikasi] !== undefined) {
                                row[klasifikasi]++;
                            } else {
                                row[klasifikasi] = 1;
                            }
                        }
                    }
                });
            }
            return row;
        });

        const totalRow = {
            "BULAN": "TOTAL",
            "ELEKTIF": report.reduce((s, r) => s + (r.ELEKTIF || 0), 0),
            "CITO": report.reduce((s, r) => s + (r.CITO || 0), 0),
            "KHUSUS": report.reduce((s, r) => s + (r.KHUSUS || 0), 0),
            "BESAR": report.reduce((s, r) => s + (r.BESAR || 0), 0),
            "SEDANG": report.reduce((s, r) => s + (r.SEDANG || 0), 0),
            "KECIL": report.reduce((s, r) => s + (r.KECIL || 0), 0)
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

// ─── WhatsApp Cron Job ────────────────────────────────────────────────────────

/**
 * Send a WhatsApp message via Fonnte API.
 * @param {string} target - Phone number of the recipient.
 * @param {string} message - Message body.
 */
async function sendWhatsAppMessage(target, message) {
    const token = process.env.FONNTE_TOKEN;
    if (!token) {
        console.error('[Cron] FONNTE_TOKEN is not set in environment variables.');
        return { success: false, error: 'FONNTE_TOKEN not set' };
    }

    const formData = new URLSearchParams();
    formData.append('target', target);
    formData.append('message', message);
    formData.append('countryCode', '62');

    try {
        const response = await fetch('https://api.fonnte.com/send', {
            method: 'POST',
            headers: {
                'Authorization': token,
            },
            body: formData,
        });
        const result = await response.json();
        console.log(`[Cron] Sent WA to ${target}:`, result);
        return { success: result.status === true, status: result.status, response: result };
    } catch (err) {
        console.error(`[Cron] Failed to send WA to ${target}:`, err.message);
        return { success: false, error: err.message };
    }
}

/**
 * Main daily job:
 * 1. Find all surgeries for D+2 (two days from now) in pendaftaran_operasi.
 * 2. Group them by ruangan_rawat_inap.
 * 3. For each unique room, look up the WhatsApp number in mst_parameter
 *    (param_type = 'RUANG_RAWAT_INAP', param_name = ruangan_rawat_inap value).
 * 4. Send a WhatsApp notification with the surgery list.
 * 5. Log each execution result to cron_job_logs table.
 */
async function runDailyWhatsAppJob() {
    // Helper: current datetime as ISO string in UTC+7 (Asia/Jakarta)
    const nowWIB = () => {
        const d = new Date();
        return d.toLocaleString('sv-SE', { timeZone: 'Asia/Jakarta' }).replace(' ', 'T') + '+07:00';
    };

    const startedAt = nowWIB();
    console.log('[Cron] Running daily WhatsApp job at', startedAt);

    // Insert initial log row and get its ID
    const { data: logRow, error: logInsertError } = await supabase
        .from('cron_job_logs')
        .insert({
            job_name: 'daily_whatsapp_notification',
            status: 'running',
            started_at: startedAt,
            timestamp: startedAt,
        })
        .select('id')
        .single();

    if (logInsertError) {
        console.error('[Cron] Failed to insert log row:', logInsertError.message);
    }
    const logId = logRow?.id || null;

    const updateLog = async (status, summary, details = null) => {
        if (!logId) return;
        await supabase
            .from('cron_job_logs')
            .update({
                status,
                summary,
                details: details ? JSON.stringify(details) : null,
                finished_at: nowWIB(),
            })
            .eq('id', logId);
    };

    try {
        // 1. Get D+2 date in WIB (YYYY-MM-DD)
        const d2Date = new Date();
        d2Date.setDate(d2Date.getDate() + 2);
        const targetDate = d2Date.toLocaleDateString('en-CA', { timeZone: 'Asia/Jakarta' });

        console.log(`[Cron] Fetching surgeries for D+2: ${targetDate}`);

        const { data: surgeries, error: sError } = await supabase
            .from('pendaftaran_operasi')
            .select('nama_pasien, no_rekam_medis, dokter_operator, dokter_anestesi, jam_rencana_operasi, jenis_operasi, ruangan_rawat_inap, diagnosis, nomor_telp_1, nomor_telp_2, ruang_operasi')
            .eq('tanggal_rencana_operasi', targetDate)
            .order('ruangan_rawat_inap', { ascending: true })
            .order('jam_rencana_operasi', { ascending: true });

        if (sError) throw sError;

        if (!surgeries || surgeries.length === 0) {
            const msg = `No surgeries found for ${targetDate}. No messages sent.`;
            console.log(`[Cron] ${msg}`);
            await updateLog('success', msg);
            return { status: 'success', summary: msg, targetDate, rooms: [], total_surgeries: 0 };
        }

        // 3. Group surgeries by ruangan_rawat_inap
        const groupedByRoom = surgeries.reduce((acc, s) => {
            const room = s.ruangan_rawat_inap || 'TIDAK DIKETAHUI';
            if (!acc[room]) acc[room] = [];
            acc[room].push(s);
            return acc;
        }, {});

        const uniqueRooms = Object.keys(groupedByRoom);
        console.log(`[Cron] Found ${surgeries.length} surgeries across ${uniqueRooms.length} room(s):`, uniqueRooms);

        const roomResults = [];

        // 4. For each room, find the WA number from mst_parameter and send message
        for (const roomName of uniqueRooms) {
            // Lookup: param_type = 'RUANG_RAWAT_INAP', param_name = roomName
            const { data: param, error: pError } = await supabase
                .from('mst_parameter')
                .select('param_value, param_name')
                .eq('param_type', 'RUANG_RAWAT_INAP')
                .eq('param_name', roomName)
                .eq('is_active', true)
                .maybeSingle();

            if (pError) {
                const msg = `Error looking up param for room "${roomName}": ${pError.message}`;
                console.error(`[Cron] ${msg}`);
                roomResults.push({ room: roomName, status: 'error', reason: msg });
                continue;
            }

            if (!param || !param.param_value) {
                const msg = `No phone number found for room "${roomName}" in mst_parameter, skipping.`;
                console.warn(`[Cron] ${msg}`);
                roomResults.push({ room: roomName, status: 'skipped', reason: msg });
                continue;
            }

            const phoneNumber = param.param_value;
            const displayName = param.param_name || roomName;
            const roomSurgeries = groupedByRoom[roomName];

            // Build message
            const lines = roomSurgeries.map((s, i) => {
                const jam = s.jam_rencana_operasi ? s.jam_rencana_operasi.substring(0, 5) : '-';
                return `${i + 1}. ${s.nama_pasien} (${s.no_rekam_medis || '-'})`
                    + `\n   Dokter Operator: ${s.dokter_operator || '-'}`
                    + `\n   Dokter Anestesi: ${s.dokter_anestesi || '-'}`
                    + `\n   Jam     : ${jam}`
                    + `\n   Jenis   : ${s.jenis_operasi || '-'}`
                    + `\n   Telp 1  : ${s.nomor_telp_1 || '-'}`
                    + `\n   Telp 2  : ${s.nomor_telp_2 || '-'}`
                    + `\n   Ruang OK: ${s.ruang_operasi || '-'}`
                    + `\n   Diagnosis: ${s.diagnosis || '-'}`;
            }).join('\n\n');

            const message = `Selamat pagi, ${displayName}!\n\nInformasi jadwal operasi *H-2* (${targetDate}):\n\n${lines}\n\nTotal: ${roomSurgeries.length} operasi.\n\n_Pesan ini dikirim otomatis oleh SORA (Smart Operating Room Access)._`;

            console.log(`[Cron] Sending WA to ${displayName} (${phoneNumber}) for room "${roomName}"...`);
            const sendResult = await sendWhatsAppMessage(phoneNumber, message);

            roomResults.push({
                room: roomName,
                phone: phoneNumber,
                status: sendResult?.success ? 'sent' : 'send_failed',
                surgery_count: roomSurgeries.length,
                wa_response: sendResult,
            });
        }

        const summary = `Job completed for ${targetDate}. Rooms processed: ${uniqueRooms.length}. Total surgeries: ${surgeries.length}.`;
        console.log(`[Cron] ${summary}`);
        await updateLog('success', summary, { targetDate, rooms: roomResults });
        return { status: 'success', summary, targetDate, rooms: roomResults, total_surgeries: surgeries.length };

    } catch (err) {
        console.error('[Cron] Job failed:', err.message);
        await updateLog('error', `Job failed: ${err.message}`);
        return { status: 'error', summary: `Job failed: ${err.message}` };
    }
}

/**
 * @openapi
 * /api/cron/whatsapp-daily:
 *   get:
 *     summary: Vercel Cron endpoint to trigger the daily WhatsApp job
 *     responses:
 *       200:
 *         description: Job triggered successfully.
 *       401:
 *         description: Unauthorized.
 */
app.get('/api/cron/whatsapp-daily', async (req, res) => {
    // Security check: Vercel Cron sends a secret in the Authorization header
    // OR it sends specific headers if triggered by Vercel
    const authHeader = req.headers['authorization'];
    const cronSecret = process.env.CRON_SECRET;

    // Validate request: Either check for Vercel Cron header or CRON_SECRET in Authorization
    const isVercelCron = req.headers['x-vercel-cron'] === '1';
    const isAuthorized = cronSecret && authHeader === `Bearer ${cronSecret}`;

    if (!isVercelCron && !isAuthorized) {
        console.warn('[Cron] Unauthorized trigger attempt for /api/cron/whatsapp-daily');
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        const result = await runDailyWhatsAppJob();
        res.json({
            message: 'WhatsApp daily cron job executed.',
            result
        });
    } catch (err) {
        console.error('[Cron] Endpoint error:', err);
        res.status(500).json({ error: 'Internal server error', details: err.message });
    }
});

// Schedule: every day at 07:00 WIB (Asia/Jakarta)
// Only schedule node-cron if NOT running on Vercel to avoid duplicates 
// and because node-cron is unreliable in serverless.
if (!process.env.VERCEL) {
    cron.schedule('0 7 * * *', runDailyWhatsAppJob, {
        timezone: 'Asia/Jakarta',
    });
    console.log('[Cron] Local WhatsApp daily job scheduled at 07:00 Asia/Jakarta.');
} else {
    console.log('[Cron] Running on Vercel: node-cron scheduler disabled (Using Vercel Crons instead).');
}

/**
 * @openapi
 * /api/test-whatsapp-job:
 *   get:
 *     summary: Manually trigger the daily WhatsApp cron job (for testing)
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Job triggered.
 */
app.get('/api/test-whatsapp-job', authenticateToken, async (req, res) => {
    try {
        const result = await runDailyWhatsAppJob();
        res.json({
            message: 'WhatsApp job completed.',
            result: result || null
        });
    } catch (err) {
        res.status(500).json({
            message: 'WhatsApp job failed.',
            error: err.message
        });
    }
});

/**
 * @openapi
 * /api/cron/whatsapp-status:
 *   get:
 *     summary: Get WhatsApp notification status for surgeries on a specific date (defaults to D+2)
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: date
 *         description: Target date for surgery (YYYY-MM-DD)
 *         schema:
 *           type: string
 *           format: date
 *     responses:
 *       200:
 *         description: List of rooms with their notification status.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 target_date:
 *                   type: string
 *                 total_surgeries:
 *                   type: integer
 *                 rooms:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       room:
 *                         type: string
 *                       surgery_count:
 *                         type: integer
 *                       log_surgery_count:
 *                         type: integer
 *                       has_updates:
 *                         type: boolean
 *                       status:
 *                         type: string
 *                       phone:
 *                         type: string
 *                       failure_reason:
 *                         type: string
 *                       last_attempt:
 *                         type: string
 */
app.get('/api/cron/whatsapp-status', authenticateToken, async (req, res) => {
    try {
        let { date, executionDate } = req.query;
        const originalParams = { date, executionDate };

        // Helper to format date as YYYY-MM-DD in Asia/Jakarta
        const formatDate = (d) => {
            return d.toLocaleDateString('en-CA', { timeZone: 'Asia/Jakarta' });
        };

        // 1. Logic for date calculation
        if (executionDate && executionDate.trim() !== '') {
            // If executionDate is provided, target is executionDate + 2
            const d = new Date(executionDate);
            if (!isNaN(d.getTime())) {
                d.setDate(d.getDate() + 2);
                date = formatDate(d);
            }
        } else if (date && date.trim() !== '') {
            // If date is provided directly, use it as is (target date)
            // No changes needed, date is already what we want
        } else {
            // Default to today + 2
            const d = new Date();
            d.setDate(d.getDate() + 2);
            date = formatDate(d);
        }

        // 2. Fetch all surgeries for the target date
        const { data: surgeries, error: sError } = await supabase
            .from('pendaftaran_operasi')
            .select('ruangan_rawat_inap, nama_pasien')
            .eq('tanggal_rencana_operasi', date);

        if (sError) throw sError;

        // 3. Get unique rooms and surgery counts
        const roomCounts = (surgeries || []).reduce((acc, s) => {
            const room = s.ruangan_rawat_inap || 'TIDAK DIKETAHUI';
            acc[room] = (acc[room] || 0) + 1;
            return acc;
        }, {});

        const uniqueRooms = Object.keys(roomCounts);

        // 4. Fetch room phone numbers from mst_parameter for these rooms
        const { data: roomParams, error: rpError } = await supabase
            .from('mst_parameter')
            .select('param_name, param_value')
            .eq('param_type', 'RUANG_RAWAT_INAP')
            .in('param_name', uniqueRooms)
            .eq('is_active', true);

        const roomPhones = (roomParams || []).reduce((acc, p) => {
            acc[p.param_name] = p.param_value;
            return acc;
        }, {});

        // 5. Fetch the most recent cron log that matches the target date in summary or details
        // We look for the most recent log where summary contains the date
        const { data: logs, error: lError } = await supabase
            .from('cron_job_logs')
            .select('status, summary, details, timestamp')
            .eq('job_name', 'daily_whatsapp_notification')
            .ilike('summary', `%${date}%`)
            .order('timestamp', { ascending: false })
            .limit(1);

        if (lError) throw lError;

        const latestLog = logs && logs.length > 0 ? logs[0] : null;
        let logResults = {};

        // 6. Parse log details if available
        if (latestLog && latestLog.details) {
            try {
                const detailsObj = typeof latestLog.details === 'string' ? JSON.parse(latestLog.details) : latestLog.details;
                if (detailsObj && detailsObj.rooms) {
                    detailsObj.rooms.forEach(r => {
                        logResults[r.room] = {
                            status: r.status,
                            phone: r.phone || null,
                            reason: r.reason || null
                        };
                    });
                }
            } catch (pErr) {
                console.error('[Status API] Error parsing log details:', pErr);
            }
        }

        // 7. Build final status list
        const results = uniqueRooms.map(room => {
            const logEntry = logResults[room];
            let status = 'need_resend';
            let phone = roomPhones[room] || null; // Fallback to mst_parameter
            let failureReason = null;
            let logSurgeryCount = 0;
            let hasUpdates = false;

            if (logEntry) {
                status = logEntry.status; // 'sent', 'send_failed', 'skipped'
                if (logEntry.phone) phone = logEntry.phone; // Prefer log phone if exists
                failureReason = logEntry.reason;

                // Extract surgery count from the log if it exists in the log details (we need to ensure it's logged)
                // Note: The cron and resend endpoints store surgery_count in the room results
                // Let's re-parse details to get surgery_count specifically for this room
                if (latestLog && latestLog.details) {
                    try {
                        const detailsObj = typeof latestLog.details === 'string' ? JSON.parse(latestLog.details) : latestLog.details;
                        const roomLog = detailsObj.rooms?.find(r => r.room === room);
                        if (roomLog) {
                            logSurgeryCount = roomLog.surgery_count || 0;
                        }
                    } catch (e) { }
                }

                // Detect if actual count is different from logged count
                if (status === 'sent' && roomCounts[room] > logSurgeryCount) {
                    hasUpdates = true;
                }
            } else {
                // If no log entry, it's definitely an update (or first time)
                hasUpdates = roomCounts[room] > 0;
            }

            return {
                room,
                surgery_count: roomCounts[room],
                log_surgery_count: logSurgeryCount,
                has_updates: hasUpdates,
                status,
                phone,
                failure_reason: failureReason,
                last_attempt: latestLog ? latestLog.timestamp : null
            };
        });

        res.json({
            target_date: date,
            total_surgeries: surgeries ? surgeries.length : 0,
            rooms: results,
            overall_log_status: latestLog ? latestLog.status : 'no_log_found',
            debug: {
                original_params: originalParams,
                calculated_target_date: date,
                server_time: new Date().toISOString()
            }
        });

    } catch (err) {
        console.error('WhatsApp status error:', err);
        res.status(500).json({ error: 'Internal server error', details: err.message });
    }
});

/**
 * @openapi
 * /api/cron/whatsapp-resend:
 *   post:
 *     summary: Manually resend WhatsApp notification for a specific room and date
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - date
 *               - room
 *             properties:
 *               date:
 *                 type: string
 *                 format: date
 *               room:
 *                 type: string
 *     responses:
 *       200:
 *         description: Resend attempt completed.
 */
app.post('/api/cron/whatsapp-resend', authenticateToken, async (req, res) => {
    const { date, room } = req.body;

    if (!date || !room) {
        return res.status(400).json({ error: 'date and room are required' });
    }

    try {
        console.log(`[Resend] Manually triggering WA for room: ${room}, date: ${date}`);

        // 1. Fetch surgeries for this specific room and date
        const { data: surgeries, error: sError } = await supabase
            .from('pendaftaran_operasi')
            .select('nama_pasien, no_rekam_medis, dokter_operator, dokter_anestesi, jam_rencana_operasi, jenis_operasi, ruangan_rawat_inap, diagnosis, nomor_telp_1, nomor_telp_2')
            .eq('tanggal_rencana_operasi', date)
            .eq('ruangan_rawat_inap', room)
            .order('jam_rencana_operasi', { ascending: true });

        if (sError) throw sError;

        if (!surgeries || surgeries.length === 0) {
            return res.status(404).json({ error: `No surgeries found for room "${room}" on ${date}.` });
        }

        // 2. Lookup phone number
        const { data: param, error: pError } = await supabase
            .from('mst_parameter')
            .select('param_value, param_name')
            .eq('param_type', 'RUANG_RAWAT_INAP')
            .eq('param_name', room)
            .eq('is_active', true)
            .maybeSingle();

        if (pError) throw pError;

        if (!param || !param.param_value) {
            return res.status(400).json({ error: `No phone number configured for room "${room}".` });
        }

        const phoneNumber = param.param_value;
        const displayName = param.param_name || room;

        // 3. Build message (reusing same format as cron job)
        const lines = surgeries.map((s, i) => {
            const jam = s.jam_rencana_operasi ? s.jam_rencana_operasi.substring(0, 5) : '-';
            return `${i + 1}. ${s.nama_pasien} (${s.no_rekam_medis || '-'})`
                + `\n   Dokter Operator: ${s.dokter_operator || '-'}`
                + `\n   Dokter Anestesi: ${s.dokter_anestesi || '-'}`
                + `\n   Jam     : ${jam}`
                + `\n   Jenis   : ${s.jenis_operasi || '-'}`
                + `\n   Telp 1  : ${s.nomor_telp_1 || '-'}`
                + `\n   Telp 2  : ${s.nomor_telp_2 || '-'}`
                + `\n   Diagnosis: ${s.diagnosis || '-'}`;
        }).join('\n\n');

        const message = `Selamat pagi, ${displayName}!\n\nInformasi jadwal operasi *H-2* (${date}):\n\n${lines}\n\nTotal: ${surgeries.length} operasi.\n\n_Pesan ini dikirim otomatis via SORA (Manual Resend)._`;

        // 4. Send Message
        const sendResult = await sendWhatsAppMessage(phoneNumber, message);

        // 5. Update/Create Log for this date
        // Note: For simplicity and to integrate with the Status API, 
        // we'll fetch the latest log for this date and update its 'details'
        // or create a new 'manual_resend' log if no log exists.

        const { data: existingLogs } = await supabase
            .from('cron_job_logs')
            .select('*')
            .eq('job_name', 'daily_whatsapp_notification')
            .ilike('summary', `%${date}%`)
            .order('timestamp', { ascending: false })
            .limit(1);

        const latestLog = existingLogs?.[0];
        const resendStatus = {
            room: room,
            phone: phoneNumber,
            status: sendResult?.success ? 'sent' : 'send_failed',
            surgery_count: surgeries.length,
            wa_response: sendResult,
            resent_at: new Date().toISOString()
        };

        if (latestLog) {
            // Update existing log details
            let details = {};
            try {
                details = typeof latestLog.details === 'string' ? JSON.parse(latestLog.details) : (latestLog.details || {});
            } catch (e) { }

            if (!details.rooms) details.rooms = [];

            // Upsert room result in details
            const roomIdx = details.rooms.findIndex(r => r.room === room);
            if (roomIdx >= 0) {
                details.rooms[roomIdx] = resendStatus;
            } else {
                details.rooms.push(resendStatus);
            }

            await supabase
                .from('cron_job_logs')
                .update({
                    details: JSON.stringify(details),
                    summary: latestLog.summary + ` (Manual resend for ${room} at ${new Date().toLocaleTimeString()})`
                })
                .eq('id', latestLog.id);
        } else {
            // Create a new manual log entry
            await supabase
                .from('cron_job_logs')
                .insert({
                    job_name: 'daily_whatsapp_notification',
                    status: sendResult?.success ? 'success' : 'error',
                    started_at: new Date().toISOString(),
                    finished_at: new Date().toISOString(),
                    timestamp: new Date().toISOString(),
                    summary: `Manual resend for room ${room} on date ${date}`,
                    details: JSON.stringify({
                        targetDate: date,
                        rooms: [resendStatus]
                    })
                });
        }

        res.json({
            message: sendResult?.success ? 'Notification resent successfully' : 'Resend attempt failed',
            success: sendResult?.success,
            room: room,
            whatsapp_response: sendResult
        });

    } catch (err) {
        console.error('[Resend API] Error:', err);
        res.status(500).json({ error: 'Internal server error', details: err.message });
    }
});

/**
 * @openapi
 * /api/whatsapp/resend:
 *   post:
 *     summary: Manually resend WhatsApp notification for a specific room and target date
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - targetDate
 *               - room
 *             properties:
 *               targetDate:
 *                 type: string
 *                 format: date
 *               room:
 *                 type: string
 *     responses:
 *       200:
 *         description: Resend attempt completed.
 */
app.post('/api/whatsapp/resend', authenticateToken, async (req, res) => {
    const { targetDate, room } = req.body;

    if (!targetDate || !room) {
        return res.status(400).json({ error: 'targetDate and room are required' });
    }

    try {
        console.log(`[Resend] Manually triggering WA for room: ${room}, targetDate: ${targetDate}`);

        const { data: surgeries, error: sError } = await supabase
            .from('pendaftaran_operasi')
            .select('nama_pasien, no_rekam_medis, dokter_operator, dokter_anestesi, jam_rencana_operasi, jenis_operasi, ruangan_rawat_inap, diagnosis, nomor_telp_1, nomor_telp_2, ruang_operasi')
            .eq('tanggal_rencana_operasi', targetDate)
            .eq('ruangan_rawat_inap', room)
            .order('jam_rencana_operasi', { ascending: true });

        if (sError) throw sError;

        if (!surgeries || surgeries.length === 0) {
            return res.status(404).json({ error: `No surgeries found for room "${room}" on ${targetDate}.` });
        }

        // 2. Lookup phone number
        const { data: param, error: pError } = await supabase
            .from('mst_parameter')
            .select('param_value, param_name')
            .eq('param_type', 'RUANG_RAWAT_INAP')
            .eq('param_name', room)
            .eq('is_active', true)
            .maybeSingle();

        if (pError) throw pError;

        if (!param || !param.param_value) {
            return res.status(400).json({ error: `No phone number configured for room "${room}".` });
        }

        const phoneNumber = param.param_value;
        const displayName = param.param_name || room;

        // 3. Build message (reusing same format as cron job)
        const lines = surgeries.map((s, i) => {
            const jam = s.jam_rencana_operasi ? s.jam_rencana_operasi.substring(0, 5) : '-';
            return `${i + 1}. ${s.nama_pasien} (${s.no_rekam_medis || '-'})`
                + `\n   Dokter Operator: ${s.dokter_operator || '-'}`
                + `\n   Dokter Anestesi: ${s.dokter_anestesi || '-'}`
                + `\n   Jam     : ${jam}`
                + `\n   Jenis   : ${s.jenis_operasi || '-'}`
                + `\n   Telp 1  : ${s.nomor_telp_1 || '-'}`
                + `\n   Telp 2  : ${s.nomor_telp_2 || '-'}`
                + `\n   Ruang OK: ${s.ruang_operasi || '-'}`
                + `\n   Diagnosis: ${s.diagnosis || '-'}`;
        }).join('\n\n');

        const message = `Selamat pagi, ${displayName}!\n\nInformasi jadwal operasi (${targetDate}):\n\n${lines}\n\nTotal: ${surgeries.length} operasi.\n\n_Pesan ini dikirim otomatis via SORA (Manual Resend)._`;

        // 4. Send Message
        const sendResult = await sendWhatsAppMessage(phoneNumber, message);

        // 5. Update/Create Log for this date
        const { data: existingLogs } = await supabase
            .from('cron_job_logs')
            .select('*')
            .eq('job_name', 'daily_whatsapp_notification')
            .ilike('summary', `%${targetDate}%`)
            .order('timestamp', { ascending: false })
            .limit(1);

        const latestLog = existingLogs?.[0];
        const resendStatus = {
            room: room,
            phone: phoneNumber,
            status: sendResult?.success ? 'sent' : 'send_failed',
            surgery_count: surgeries.length,
            wa_response: sendResult,
            resent_at: new Date().toISOString()
        };

        if (latestLog) {
            // Update existing log details
            let details = {};
            try {
                details = typeof latestLog.details === 'string' ? JSON.parse(latestLog.details) : (latestLog.details || {});
            } catch (e) { }

            if (!details.rooms) details.rooms = [];

            // Upsert room result in details
            const roomIdx = details.rooms.findIndex(r => r.room === room);
            if (roomIdx >= 0) {
                details.rooms[roomIdx] = resendStatus;
            } else {
                details.rooms.push(resendStatus);
            }

            await supabase
                .from('cron_job_logs')
                .update({
                    details: JSON.stringify(details),
                    summary: latestLog.summary + ` (Manual resend for ${room} at ${new Date().toLocaleTimeString()})`
                })
                .eq('id', latestLog.id);
        } else {
            // Create a new manual log entry
            await supabase
                .from('cron_job_logs')
                .insert({
                    job_name: 'daily_whatsapp_notification',
                    status: sendResult?.success ? 'success' : 'error',
                    started_at: new Date().toISOString(),
                    finished_at: new Date().toISOString(),
                    timestamp: new Date().toISOString(),
                    summary: `Manual resend for room ${room} on date ${targetDate}`,
                    details: JSON.stringify({
                        targetDate: targetDate,
                        rooms: [resendStatus]
                    })
                });
        }

        res.json({
            message: sendResult?.success ? 'Notification resent successfully' : 'Resend attempt failed',
            success: sendResult?.success,
            room: room,
            whatsapp_response: sendResult
        });

    } catch (err) {
        console.error('[Resend API] Error:', err);
        res.status(500).json({ error: 'Internal server error', details: err.message });
    }
});

/**
 * @openapi
 * /api/cron-logs:
 *   get:
 *     summary: Get cron job execution logs with date filter and pagination
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: date
 *         description: Filter by date (YYYY-MM-DD) on the timestamp column
 *         schema:
 *           type: string
 *           format: date
 *       - in: query
 *         name: job_name
 *         description: Filter by job name
 *         schema:
 *           type: string
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *       - in: query
 *         name: pageSize
 *         schema:
 *           type: integer
 *           default: 20
 *     responses:
 *       200:
 *         description: Paginated list of cron job logs.
 */
// Get Cron Logs API
app.get('/api/cron-logs', authenticateToken, async (req, res) => {
    try {
        const { date, job_name, page = 1, pageSize = 20 } = req.query;
        const pageNum = parseInt(page);
        const sizeNum = parseInt(pageSize);
        const from = (pageNum - 1) * sizeNum;
        const to = from + sizeNum - 1;

        let query = supabase
            .from('cron_job_logs')
            .select('*', { count: 'exact' });

        // Filter by date on the timestamp column (started_at)
        if (date) {
            const startOfDay = `${date}T00:00:00.000+07:00`;
            const endOfDay = `${date}T23:59:59.999+07:00`;
            query = query.gte('timestamp', startOfDay).lte('timestamp', endOfDay);
        }

        // Filter by job name
        if (job_name) {
            query = query.eq('job_name', job_name);
        }

        const { data: logs, error, count } = await query
            .order('timestamp', { ascending: false })
            .range(from, to);

        if (error) throw error;

        res.json({
            data: logs,
            pagination: {
                total: count,
                page: pageNum,
                pageSize: sizeNum,
                totalPages: Math.ceil(count / sizeNum),
            },
        });
    } catch (err) {
        console.error('Fetch cron logs error:', err);
        res.status(500).json({ error: 'Internal server error' });
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

