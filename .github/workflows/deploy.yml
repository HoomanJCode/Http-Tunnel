name: Deploy HTTP Tunnel Server

on:
  push:
    branches: [master]
  workflow_dispatch:

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: webfactory/ssh-agent@v0.9.0
        with:
          ssh-private-key: ${{ secrets.VPS_SSH_PRIVATE_KEY }}

      - name: Deploy
        env:
          # Required secrets
          VPS_HOST: ${{ secrets.VPS_HOST }}
          ENCRYPTION_KEY: ${{ secrets.ENCRYPTION_KEY }}
          
          # Optional secrets (defaults used if not set)
          VPS_USER: ${{ secrets.VPS_USER || 'root' }}
          VPS_PORT: ${{ secrets.VPS_PORT || '22' }}
          LISTEN_HOST: ${{ secrets.LISTEN_HOST || '0.0.0.0' }}
          LISTEN_PORT: ${{ secrets.LISTEN_PORT || '8080' }}
          TCP_TIMEOUT: ${{ secrets.TCP_TIMEOUT || '60' }}
          UDP_TIMEOUT: ${{ secrets.UDP_TIMEOUT || '120' }}
          CONNECT_TIMEOUT: ${{ secrets.CONNECT_TIMEOUT || '8' }}
          CLEANUP_INTERVAL: ${{ secrets.CLEANUP_INTERVAL || '30' }}
          RECV_BUFFER: ${{ secrets.RECV_BUFFER || '131072' }}
          SEND_BUFFER: ${{ secrets.SEND_BUFFER || '131072' }}
          READ_CHUNK: ${{ secrets.READ_CHUNK || '65536' }}
          READ_TIMEOUT: ${{ secrets.READ_TIMEOUT || '0.01' }}
          READ_EXTEND: ${{ secrets.READ_EXTEND || '0.03' }}
          UDP_READ_TIMEOUT: ${{ secrets.UDP_READ_TIMEOUT || '0.3' }}
          MAX_POST_BYTES: ${{ secrets.MAX_POST_BYTES || '5242880' }}
          LOG_LEVEL: ${{ secrets.LOG_LEVEL || 'INFO' }}
        run: python3 deploy.py