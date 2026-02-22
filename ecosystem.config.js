// ecosystem.config.js — PM2 process manager config
module.exports = {
  apps: [
    {
      name: 'linsaftw-blog-backend',
      script: 'server.js',
      cwd: __dirname,
      env: {
        NODE_ENV: 'production',
      },
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '512M',
      error_file: './logs/err.log',
      out_file: './logs/out.log',
      log_file: './logs/combined.log',
      time: true,
    },
  ],
};
