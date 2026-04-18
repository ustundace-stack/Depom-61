export default function Banner() {
  return (
    <div className="bg-orange-100 py-3 text-center">
      <div className="max-w-6xl mx-auto px-4 flex items-center justify-center gap-4">
        <span className="text-sm text-gray-700">
          Online Türkiye Geneli Denemeler Tam Başarı Paketinde devam ediyor!
        </span>
        <button className="bg-primary text-white px-6 py-2 rounded-full text-sm font-medium hover:bg-orange-500">
          Giriş
        </button>
      </div>
    </div>
  )
}
