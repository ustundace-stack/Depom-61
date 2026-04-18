export default function Footer() {
  return (
    <footer className="bg-dark text-white py-12">
      <div className="max-w-6xl mx-auto px-4">
        <div className="grid md:grid-cols-4 gap-8 mb-8">
          <div>
            <h3 className="font-bold mb-4 flex items-center gap-2">
              <span className="text-2xl">🎓</span>
              Okulistik Marka
            </h3>
            <p className="text-gray-400 text-sm">
              Türkiye'nin lider online eğitim platformu
            </p>
          </div>
          <div>
            <h4 className="font-bold mb-4">Hızlı Bağlantılar</h4>
            <ul className="space-y-2 text-sm text-gray-400">
              <li><a href="#" className="hover:text-primary">Hakkımızda</a></li>
              <li><a href="#" className="hover:text-primary">İletişim</a></li>
              <li><a href="#" className="hover:text-primary">Blog</a></li>
            </ul>
          </div>
          <div>
            <h4 className="font-bold mb-4">Yasal</h4>
            <ul className="space-y-2 text-sm text-gray-400">
              <li><a href="#" className="hover:text-primary">Kullanım Şartları</a></li>
              <li><a href="#" className="hover:text-primary">Gizlilik Politikası</a></li>
              <li><a href="#" className="hover:text-primary">KVKK</a></li>
            </ul>
          </div>
          <div>
            <h4 className="font-bold mb-4">İletişim</h4>
            <ul className="space-y-2 text-sm text-gray-400">
              <li>Email: info@okulistik.com</li>
              <li>Tel: +90 (212) 000 0000</li>
              <li>Adres: İstanbul, Türkiye</li>
            </ul>
          </div>
        </div>

        <div className="border-t border-gray-700 pt-8 text-center text-sm text-gray-400">
          <p>&copy; 2026 Okulistik. Tüm hakları saklıdır. Türkiye Geneli 3.</p>
        </div>
      </div>
    </footer>
  )
}
