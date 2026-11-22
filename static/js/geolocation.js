// CyberShield - Browser Geolocation Capture
(function() {
  'use strict';
  var JAMMU_LAT = 32.7266, JAMMU_LNG = 74.8570;

  function setLocationFields(lat, lng, city) {
    var fLat = document.getElementById('real_lat');
    var fLng = document.getElementById('real_lng');
    var fLoc = document.getElementById('real_location');
    var fBase = document.getElementById('baseline_location');
    if (fLat) fLat.value = lat;
    if (fLng) fLng.value = lng;
    if (fLoc && city) fLoc.value = city;
    if (fBase && city && fBase.value === 'Jammu') fBase.value = city;
    updateGeoStatus(lat, lng, city);
  }

  function updateGeoStatus(lat, lng, city) {
    var el = document.getElementById('geo-status');
    if (!el) return;
    el.textContent = city ? 'Detected: ' + city + ' (' + lat.toFixed(4) + ', ' + lng.toFixed(4) + ')' : 'Location captured';
    el.style.color = '#00ff88';
  }

  function reverseGeocode(lat, lng) {
    fetch('https://ip-api.com/json/?fields=city,regionName,country')
      .then(function(r) { return r.json(); })
      .then(function(d) {
        var city = (d.city && d.city !== '') ? d.city : (d.regionName || 'GPS Location');
        setLocationFields(lat, lng, city);
      })
      .catch(function() { setLocationFields(lat, lng, 'GPS Location'); });
  }

  function ipFallback() {
    fetch('https://ip-api.com/json/?fields=lat,lon,city,regionName')
      .then(function(r) { return r.json(); })
      .then(function(d) {
        if (d.lat && d.lon) {
          setLocationFields(parseFloat(d.lat), parseFloat(d.lon), d.city || d.regionName || 'Unknown');
        } else {
          setLocationFields(JAMMU_LAT, JAMMU_LNG, 'Jammu');
        }
      })
      .catch(function() { setLocationFields(JAMMU_LAT, JAMMU_LNG, 'Jammu'); });
  }

  function captureLocation() {
    if (!navigator.geolocation) { ipFallback(); return; }
    navigator.geolocation.getCurrentPosition(
      function(pos) {
        var lat = parseFloat(pos.coords.latitude.toFixed(6));
        var lng = parseFloat(pos.coords.longitude.toFixed(6));
        reverseGeocode(lat, lng);
      },
      function() { ipFallback(); },
      { timeout: 8000, maximumAge: 300000 }
    );
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', captureLocation);
  } else {
    captureLocation();
  }
})();
