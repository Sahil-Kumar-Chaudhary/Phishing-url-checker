import net from 'net';
import { PortsInfo } from '../types/analysis';

const COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080];

export async function getOpenPorts(hostname: string): Promise<PortsInfo> {
  const results: PortsInfo = {};

  const checkPort = (port: number): Promise<boolean> => {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(1500); // Short timeout so it doesn't hang

      socket.on('connect', () => {
        socket.destroy();
        resolve(true);
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve(false);
      });

      socket.on('error', () => {
        resolve(false);
      });

      socket.connect(port, hostname);
    });
  };

  try {
    const checks = COMMON_PORTS.map(async (port) => {
      const isOpen = await checkPort(port);
      results[port] = isOpen;
    });

    await Promise.all(checks);
  } catch (error) {
    console.error('Error checking ports:', error);
  }

  return results;
}
