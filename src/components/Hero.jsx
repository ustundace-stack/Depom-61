export default function Hero() {
  const decorativeDots = [
    { size: 'w-2 h-2', top: 'top-20', left: 'left-10', delay: 'delay-0' },
    { size: 'w-4 h-4', top: 'top-40', left: 'left-32', delay: 'delay-100' },
    { size: 'w-3 h-3', top: 'top-48', right: 'right-20', delay: 'delay-200' },
    { size: 'w-2 h-2', top: 'top-60', right: 'right-32', delay: 'delay-300' },
    { size: 'w-5 h-5', bottom: 'bottom-40', left: 'left-20', delay: 'delay-400' },
    { size: 'w-3 h-3', bottom: 'bottom-32', right: 'right-24', delay: 'delay-500' },
  ];

  return (
    <section className="relative py-20 bg-gradient-to-b from-white to-orange-50 overflow-hidden">
      <div className="max-w-6xl mx-auto px-4">
        <div className="text-center mb-16">
          <h1 className="text-5xl font-bold text-dark mb-4">
            İlkokul ve Ortaokullar için
          </h1>
          <h2 className="text-5xl font-bold mb-6">
            <span className="text-primary">Online eğitim!</span>
          </h2>
          <div className="w-32 h-1 bg-primary mx-auto rounded-full"></div>
        </div>

        <div className="grid md:grid-cols-2 gap-8 mb-16">
          <div className="bg-white rounded-2xl p-8 shadow-lg hover:shadow-xl transition-shadow">
            <div className="text-5xl mb-4">👨‍👩‍👧</div>
            <h3 className="text-2xl font-bold text-dark mb-2">Öğrenci & Veli</h3>
            <p className="text-gray-600">
              İnteraktif dersler, çıkmış sınav soruları ve kişiselleştirilmiş öğrenme yolu.
            </p>
          </div>

          <div className="bg-white rounded-2xl p-8 shadow-lg hover:shadow-xl transition-shadow">
            <div className="text-5xl mb-4">👩‍🏫</div>
            <h3 className="text-2xl font-bold text-dark mb-2">Öğretmen & Yönetici</h3>
            <p className="text-gray-600">
              Sınıf yönetimi, öğrenci ilerleme takibi ve etkileşimli araçlar.
            </p>
          </div>
        </div>

        {/* Decorative dots */}
        {decorativeDots.map((dot, i) => (
          <div
            key={i}
            className={`dot ${dot.size} ${dot.top || ''} ${dot.bottom || ''} ${dot.left || ''} ${dot.right || ''} ${dot.delay} animate-float`}
            style={{
              backgroundColor: i % 3 === 0 ? '#FFB347' : i % 3 === 1 ? '#FFD6A5' : '#E6B8D7'
            }}
          />
        ))}

        {/* Main illustration area */}
        <div className="bg-white rounded-3xl shadow-xl p-8 relative overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-r from-orange-50 to-purple-50 opacity-50"></div>
          <div className="relative h-80 flex items-center justify-center">
            <div className="text-center">
              <div className="text-8xl mb-4">👨‍💻👩‍💻👧</div>
              <p className="text-gray-600 text-lg">
                Öğrenciler, öğretmenler ve veliler için bir araya gelmiş modern eğitim platformu
              </p>
              <button className="mt-6 bg-primary text-white px-8 py-3 rounded-full font-bold hover:bg-orange-500 transition-colors">
                Şimdi Başla
              </button>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
