-- SwimSafe seed: initial general information for Cork beaches
-- Populates safe, high-level location + access info
-- Source: locality knowledge + Google Maps via lat/lng
-- Applied once after schema migration 001

UPDATE beaches SET
  town = 'Garretstown',
  country = 'Ireland',
  parking_info = 'Informal parking is typically available near the beach. Availability may vary during busy periods.',
  facilities = 'No permanent facilities are guaranteed. Users should plan accordingly and follow local signage.',
  access_notes = 'Access is via local roads and pedestrian paths. Surfaces may be uneven in places.',
  maps_url = 'https://www.google.com/maps?q=51.643600,-8.588700'
WHERE id = 1;

UPDATE beaches SET
  town = 'Garretstown',
  country = 'Ireland',
  parking_info = 'Informal roadside parking is commonly used near the beach. Arrive early during peak times.',
  facilities = 'Facilities are limited. Visitors should be self-sufficient.',
  access_notes = 'Beach access via sand dunes and informal paths.',
  maps_url = 'https://www.google.com/maps?q=51.647400,-8.603900'
WHERE id = 2;

UPDATE beaches SET
  town = 'Fountainstown',
  country = 'Ireland',
  parking_info = 'Seasonal parking is generally available close to the beach.',
  facilities = 'Facilities may be available seasonally. Check local notices.',
  access_notes = 'Direct access from village roads and promenade.',
  maps_url = 'https://www.google.com/maps?q=51.786300,-8.314900'
WHERE id = 3;

UPDATE beaches SET
  town = 'Myrtleville',
  country = 'Ireland',
  parking_info = 'Parking is available nearby, including roadside and small car parks.',
  facilities = 'Limited facilities available in the village area.',
  access_notes = 'Easy access from village roads and slipways.',
  maps_url = 'https://www.google.com/maps?q=51.780800,-8.315300'
WHERE id = 4;

UPDATE beaches SET
  town = 'Myrtleville',
  country = 'Ireland',
  parking_info = 'Small informal parking areas are typically used.',
  facilities = 'No permanent beach facilities. Nearby village services may be available.',
  access_notes = 'Access via rocky paths; caution advised at low tide.',
  maps_url = 'https://www.google.com/maps?q=51.771900,-8.318900'
WHERE id = 5;

UPDATE beaches SET
  town = 'Myrtleville',
  country = 'Ireland',
  parking_info = 'Limited roadside parking near access points.',
  facilities = 'No guaranteed facilities at this location.',
  access_notes = 'Rocky access; suitable footwear recommended.',
  maps_url = 'https://www.google.com/maps?q=51.784200,-8.327100'
WHERE id = 6;

UPDATE beaches SET
  town = 'Clonakilty',
  country = 'Ireland',
  parking_info = 'Formal car parking is available near the beach.',
  facilities = 'Seasonal facilities may be available in nearby areas.',
  access_notes = 'Good access via boardwalks and beach paths.',
  maps_url = 'https://www.google.com/maps?q=51.598400,-8.876400'
WHERE id = 7;

UPDATE beaches SET
  town = 'Clonakilty',
  country = 'Ireland',
  parking_info = 'Parking is available close to the beach entrance.',
  facilities = 'Limited facilities available depending on season.',
  access_notes = 'Access via sandy paths and boardwalks.',
  maps_url = 'https://www.google.com/maps?q=51.588700,-8.901800'
WHERE id = 8;

UPDATE beaches SET
  town = 'Rosscarbery',
  country = 'Ireland',
  parking_info = 'Parking available near the beach, including informal areas.',
  facilities = 'No permanent facilities guaranteed.',
  access_notes = 'Long beach with multiple access points.',
  maps_url = 'https://www.google.com/maps?q=51.635800,-9.028600'
WHERE id = 9;

UPDATE beaches SET
  town = 'Rosscarbery',
  country = 'Ireland',
  parking_info = 'Informal parking commonly used by visitors.',
  facilities = 'Facilities may be limited or seasonal.',
  access_notes = 'Access via sand and dune systems.',
  maps_url = 'https://www.google.com/maps?q=51.640200,-9.048300'
WHERE id = 10;

UPDATE beaches SET
  town = 'Tragumna',
  country = 'Ireland',
  parking_info = 'Small parking areas available near the beach.',
  facilities = 'No permanent facilities on site.',
  access_notes = 'Access via local roads and beach paths.',
  maps_url = 'https://www.google.com/maps?q=51.574600,-9.036500'
WHERE id = 11;

UPDATE beaches SET
  town = 'Mizen Peninsula',
  country = 'Ireland',
  parking_info = 'Designated parking areas are available nearby.',
  facilities = 'Seasonal facilities may be available.',
  access_notes = 'Access via marked paths; dunes protected.',
  maps_url = 'https://www.google.com/maps?q=51.466900,-9.822300'
WHERE id = 12;

UPDATE beaches SET
  town = 'Skibbereen',
  country = 'Ireland',
  parking_info = 'Parking available near access points.',
  facilities = 'No beach facilities; nearby village amenities.',
  access_notes = 'Access via paths; sensitive ecological area.',
  maps_url = 'https://www.google.com/maps?q=51.505400,-9.312600'
WHERE id = 13;

UPDATE beaches SET
  town = 'Baltimore',
  country = 'Ireland',
  parking_info = 'Parking available in the village.',
  facilities = 'Facilities available within the village area.',
  access_notes = 'Harbour-side access with slipways.',
  maps_url = 'https://www.google.com/maps?q=51.483500,-9.367800'
WHERE id = 14;

UPDATE beaches SET
  town = 'Schull',
  country = 'Ireland',
  parking_info = 'Village parking available nearby.',
  facilities = 'Facilities available in the harbour area.',
  access_notes = 'Easy access from harbour walkways.',
  maps_url = 'https://www.google.com/maps?q=51.527800,-9.546200'
WHERE id = 15;

UPDATE beaches SET
  town = 'Ballycotton',
  country = 'Ireland',
  parking_info = 'Parking available near the village.',
  facilities = 'Seasonal facilities may be available.',
  access_notes = 'Access via village paths and beach entrances.',
  maps_url = 'https://www.google.com/maps?q=51.829600,-8.007900'
WHERE id = 16;

UPDATE beaches SET
  town = 'Ballycotton',
  country = 'Ireland',
  parking_info = 'Limited informal parking near access points.',
  facilities = 'No guaranteed facilities.',
  access_notes = 'Access via coastal paths.',
  maps_url = 'https://www.google.com/maps?q=51.840400,-8.002300'
WHERE id = 17;

UPDATE beaches SET
  town = 'Ballycotton',
  country = 'Ireland',
  parking_info = 'Roadside parking commonly used.',
  facilities = 'No permanent facilities.',
  access_notes = 'Access via informal coastal paths.',
  maps_url = 'https://www.google.com/maps?q=51.836700,-8.003800'
WHERE id = 18;

UPDATE beaches SET
  town = 'Ballycotton',
  country = 'Ireland',
  parking_info = 'Parking available along nearby roads.',
  facilities = 'No facilities on site.',
  access_notes = 'Access via rocky shoreline paths.',
  maps_url = 'https://www.google.com/maps?q=51.833500,-8.010200'
WHERE id = 19;

UPDATE beaches SET
  town = 'Ballycotton',
  country = 'Ireland',
  parking_info = 'Informal parking in nearby areas.',
  facilities = 'Facilities not guaranteed.',
  access_notes = 'Access via coastal trail routes.',
  maps_url = 'https://www.google.com/maps?q=51.831200,-8.013700'
WHERE id = 20;

UPDATE beaches SET
  town = 'Youghal',
  country = 'Ireland',
  parking_info = 'Formal parking available near the promenade.',
  facilities = 'Facilities available in the town area.',
  access_notes = 'Easy access via promenade and ramps.',
  maps_url = 'https://www.google.com/maps?q=51.955700,-7.850300'
WHERE id = 21;

UPDATE beaches SET
  town = 'Youghal',
  country = 'Ireland',
  parking_info = 'Parking available near beach entrances.',
  facilities = 'Facilities available nearby.',
  access_notes = 'Access via dunes and beach paths.',
  maps_url = 'https://www.google.com/maps?q=51.961800,-7.847200'
WHERE id = 22;

UPDATE beaches SET
  town = 'Kinsale',
  country = 'Ireland',
  parking_info = 'Parking available in nearby areas.',
  facilities = 'No guaranteed facilities at the beach.',
  access_notes = 'Access via harbour paths.',
  maps_url = 'https://www.google.com/maps?q=51.707300,-8.522400'
WHERE id = 23;

UPDATE beaches SET
  town = 'Kinsale',
  country = 'Ireland',
  parking_info = 'Parking available in Kinsale town.',
  facilities = 'Facilities available in town.',
  access_notes = 'Easy access via coastal paths.',
  maps_url = 'https://www.google.com/maps?q=51.702600,-8.533300'
WHERE id = 24;

UPDATE beaches SET
  town = 'Garretstown',
  country = 'Ireland',
  parking_info = 'Informal parking near beach access points.',
  facilities = 'Limited seasonal facilities may be available.',
  access_notes = 'Access via sand dunes and paths.',
  maps_url = 'https://www.google.com/maps?q=51.645300,-8.582100'
WHERE id = 25;