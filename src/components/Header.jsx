export default function Header() {
  return (
    <header className="bg-white shadow-sm">
      <div className="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
        <div className="flex items-center gap-8">
          <div className="flex items-center gap-2">
            <span className="text-2xl">🎓</span>
            <span className="text-2xl font-bold text-primary">Okulistik</span>
          </div>
          <nav className="hidden md:flex gap-6">
            <button className="text-gray-700 hover:text-primary font-medium">
              Öğrenciler için ▼
            </button>
            <button className="text-gray-700 hover:text-primary font-medium">
              Öğretmenler için ▼
            </button>
          </nav>
        </div>

        <div className="flex items-center gap-4">
          <button className="text-gray-700 hover:text-primary font-medium">
            Ücretsiz Kaydol
          </button>
          <button className="bg-primary text-white px-6 py-2 rounded-full hover:bg-orange-500 font-medium">
            Giriş Yap
          </button>
          <button className="relative">
            <span className="text-2xl">🛒</span>
            <span className="absolute -top-2 -right-2 bg-primary text-white text-xs rounded-full w-5 h-5 flex items-center justify-center">
              0
            </span>
          </button>
        </div>
      </div>
    </header>
  )
}
