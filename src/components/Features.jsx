export default function Features() {
  const features = [
    { icon: '📺', title: 'Canlı Dersler', description: 'Öğretmenlerle gerçek zamanlı etkileşim' },
    { icon: '📚', title: 'Soru Bankası', description: 'Binlerce çıkmış sınav sorusu' },
    { icon: '📊', title: 'İlerleme Takibi', description: 'Detaylı performans raporları' },
    { icon: '🏆', title: 'Yarışmalar', description: 'Ödüllü öğrenme yarışmaları' },
  ];

  return (
    <section className="py-16 bg-gray-50">
      <div className="max-w-6xl mx-auto px-4">
        <h2 className="text-3xl font-bold text-center text-dark mb-12">
          Neden <span className="text-primary">Okulistik</span>?
        </h2>

        <div className="grid md:grid-cols-4 gap-6">
          {features.map((feature, i) => (
            <div key={i} className="bg-white rounded-xl p-6 text-center hover:shadow-lg transition-shadow">
              <div className="text-4xl mb-3">{feature.icon}</div>
              <h3 className="font-bold text-dark mb-2">{feature.title}</h3>
              <p className="text-sm text-gray-600">{feature.description}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
