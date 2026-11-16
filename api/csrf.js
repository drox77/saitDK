import { api } from '../src/serverless.js';

export default (req, res) => api.run(req, res, api.csrf);
