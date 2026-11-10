import readline from 'node:readline';
import { getTags, search, getQuota, saveSession } from './index.js';

// Otomatis simpan kredensial Anda saat tools dijalankan
const myCredentials = {
  phoneNumber: '+6281234567890', // Ganti dengan nomor Anda jika perlu
  clientDeviceId: 'c83154dcc6c3f2b2',
  token: 'dkJmzW3c5d9b3f89460b3a4648cc39e3e013062da0b36a1b09e2c1eed8',
  finalKey: '7d99c77f9c7247ae21220510c02fe44aa25311c6c9dfc30ecacb6a2e51e4dfef'
};

try {
  saveSession(myCredentials);
} catch (e) {}

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function menu() {
  console.log('\n================================');
  console.log('   GETCONTACT CLI TOOLS');
  console.log('================================');
  console.log('1. Cek Sisa Kuota API');
  console.log('2. Cari Tag / Profil Nomor');
  console.log('3. Keluar');
  console.log('--------------------------------');
  
  rl.question('Pilih menu (1-3): ', async (choice) => {
    switch (choice.trim()) {
      case '1':
        try {
          console.log('\nSedang mengecek kuota...');
          const quota = await getQuota();
          console.log('\n📊 HASIL KUOTA:');
          console.log(JSON.stringify(quota, null, 2));
        } catch (err) {
          console.log('\n❌ Error:', err.message);
        }
        menu();
        break;

      case '2':
        rl.question('Masukkan nomor target (cth: +628123...): ', async (phone) => {
          try {
            console.log(`\nSedang mencari data untuk ${phone}...`);
            const result = await search(phone);
            console.log('\n🔍 HASIL PENCARIAN & TAG:');
            console.log(JSON.stringify(result, null, 2));
          } catch (err) {
            console.log('\n❌ Error:', err.message);
          }
          menu();
        });
        break;

      case '3':
        console.log('Keluar dari program. Sampai jumpa!');
        rl.close();
        process.exit(0);
        break;

      default:
        console.log('⚠️ Pilihan tidak valid, silakan coba lagi.');
        menu();
        break;
    }
  });
}

menu();
