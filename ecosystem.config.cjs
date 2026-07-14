module.exports = {
  apps: [
    {
      name: 'hvault',
      script: 'packages/server/dist/server.js',
      // Set to number of desired workers. 'max' uses all CPU cores but may exhaust memory (each instance uses up to max_memory_restart).
      instances: 2,
      exec_mode: 'cluster',
      max_memory_restart: '512M',
      kill_timeout: 35000,
      wait_ready: true,
      autorestart: true,
      max_restarts: 15,
      min_uptime: '10s',
      restart_delay: 5000,
      error_file: 'logs/error.log',
      out_file: 'logs/out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      env: {
        NODE_ENV: 'development',
        PORT: 5000,
      },
      env_production: {
        NODE_ENV: 'production',
        PORT: 5000,
      },
    },
  ],
};
