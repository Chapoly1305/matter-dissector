# Cluster Completion TODO (Matter v1.5)

Generated at: `2026-02-19 00:38 UTC`

## Scope
- Source baseline: `connectedhomeip v1.5-branch`
- Tracking target: `ws-4.6.3` full IM/cluster parsing completion

## Global Status
- [x] Full cluster/attribute/command/event ID-to-name mapping in IM paths
- [x] Generic IM attribute payload decode (primitive typed values)
- [x] Generic IM command payload decode with field-name mapping
- [x] Generic IM event payload decode with field-name mapping

## Per-Cluster Checklist
Legend:
- `Path decode`: Cluster/Attribute/Command/Event path IDs decoded to names
- `Attribute payload`: Attribute data/status payload fields decoded structurally
- `Command payload`: Command request/response payload fields decoded structurally
- `Event payload`: Event payload fields decoded structurally

### Identify (`0x00000003`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### Groups (`0x00000004`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### OnOff (`0x00000006`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### LevelControl (`0x00000008`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### PulseWidthModulation (`0x0000001C`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### Descriptor (`0x0000001D`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### Binding (`0x0000001E`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### AccessControl (`0x0000001F`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### Actions (`0x00000025`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### BasicInformation (`0x00000028`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### OtaSoftwareUpdateProvider (`0x00000029`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### OtaSoftwareUpdateRequestor (`0x0000002A`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### LocalizationConfiguration (`0x0000002B`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### TimeFormatLocalization (`0x0000002C`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### UnitLocalization (`0x0000002D`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### PowerSourceConfiguration (`0x0000002E`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### PowerSource (`0x0000002F`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### GeneralCommissioning (`0x00000030`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### NetworkCommissioning (`0x00000031`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### DiagnosticLogs (`0x00000032`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### GeneralDiagnostics (`0x00000033`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### SoftwareDiagnostics (`0x00000034`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### ThreadNetworkDiagnostics (`0x00000035`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### WiFiNetworkDiagnostics (`0x00000036`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### EthernetNetworkDiagnostics (`0x00000037`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### TimeSynchronization (`0x00000038`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### BridgedDeviceBasicInformation (`0x00000039`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### Switch (`0x0000003B`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### AdministratorCommissioning (`0x0000003C`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### OperationalCredentials (`0x0000003E`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### GroupKeyManagement (`0x0000003F`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### FixedLabel (`0x00000040`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### UserLabel (`0x00000041`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### ProxyConfiguration (`0x00000042`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### ProxyDiscovery (`0x00000043`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### ProxyValid (`0x00000044`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### BooleanState (`0x00000045`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### IcdManagement (`0x00000046`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### Timer (`0x00000047`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### OvenCavityOperationalState (`0x00000048`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### OvenMode (`0x00000049`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### LaundryDryerControls (`0x0000004A`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### ModeSelect (`0x00000050`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### LaundryWasherMode (`0x00000051`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### RefrigeratorAndTemperatureControlledCabinetMode (`0x00000052`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### LaundryWasherControls (`0x00000053`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### RvcRunMode (`0x00000054`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### RvcCleanMode (`0x00000055`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### TemperatureControl (`0x00000056`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### RefrigeratorAlarm (`0x00000057`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### DishwasherMode (`0x00000059`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### AirQuality (`0x0000005B`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### SmokeCoAlarm (`0x0000005C`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### DishwasherAlarm (`0x0000005D`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### MicrowaveOvenMode (`0x0000005E`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### MicrowaveOvenControl (`0x0000005F`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### OperationalState (`0x00000060`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### RvcOperationalState (`0x00000061`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### ScenesManagement (`0x00000062`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### Groupcast (`0x00000065`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### HepaFilterMonitoring (`0x00000071`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### ActivatedCarbonFilterMonitoring (`0x00000072`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### WaterTankLevelMonitoring (`0x00000079`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### BooleanStateConfiguration (`0x00000080`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### ValveConfigurationAndControl (`0x00000081`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### ElectricalPowerMeasurement (`0x00000090`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### ElectricalEnergyMeasurement (`0x00000091`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### WaterHeaterManagement (`0x00000094`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### CommodityPrice (`0x00000095`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### Messages (`0x00000097`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### DeviceEnergyManagement (`0x00000098`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### EnergyEvse (`0x00000099`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### EnergyPreference (`0x0000009B`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### PowerTopology (`0x0000009C`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### EnergyEvseMode (`0x0000009D`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### WaterHeaterMode (`0x0000009E`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### DeviceEnergyManagementMode (`0x0000009F`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### ElectricalGridConditions (`0x000000A0`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### DoorLock (`0x00000101`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### WindowCovering (`0x00000102`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### ClosureControl (`0x00000104`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### ClosureDimension (`0x00000105`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### ServiceArea (`0x00000150`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### PumpConfigurationAndControl (`0x00000200`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### Thermostat (`0x00000201`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### FanControl (`0x00000202`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### ThermostatUserInterfaceConfiguration (`0x00000204`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### ColorControl (`0x00000300`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### BallastConfiguration (`0x00000301`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### IlluminanceMeasurement (`0x00000400`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### TemperatureMeasurement (`0x00000402`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### PressureMeasurement (`0x00000403`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### FlowMeasurement (`0x00000404`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### RelativeHumidityMeasurement (`0x00000405`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### OccupancySensing (`0x00000406`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### CarbonMonoxideConcentrationMeasurement (`0x0000040C`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### CarbonDioxideConcentrationMeasurement (`0x0000040D`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### NitrogenDioxideConcentrationMeasurement (`0x00000413`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### OzoneConcentrationMeasurement (`0x00000415`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### Pm25ConcentrationMeasurement (`0x0000042A`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### FormaldehydeConcentrationMeasurement (`0x0000042B`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### Pm1ConcentrationMeasurement (`0x0000042C`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### Pm10ConcentrationMeasurement (`0x0000042D`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### TotalVolatileOrganicCompoundsConcentrationMeasurement (`0x0000042E`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### RadonConcentrationMeasurement (`0x0000042F`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### SoilMeasurement (`0x00000430`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### WiFiNetworkManagement (`0x00000451`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### ThreadBorderRouterManagement (`0x00000452`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### ThreadNetworkDirectory (`0x00000453`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### WakeOnLan (`0x00000503`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### Channel (`0x00000504`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### TargetNavigator (`0x00000505`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### MediaPlayback (`0x00000506`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### MediaInput (`0x00000507`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### LowPower (`0x00000508`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### KeypadInput (`0x00000509`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### ContentLauncher (`0x0000050A`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### AudioOutput (`0x0000050B`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### ApplicationLauncher (`0x0000050C`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### ApplicationBasic (`0x0000050D`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### AccountLogin (`0x0000050E`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### ContentControl (`0x0000050F`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### ContentAppObserver (`0x00000510`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### ZoneManagement (`0x00000550`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### CameraAvStreamManagement (`0x00000551`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### CameraAvSettingsUserLevelManagement (`0x00000552`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### WebRTCTransportProvider (`0x00000553`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### WebRTCTransportRequestor (`0x00000554`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### PushAvStreamTransport (`0x00000555`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### Chime (`0x00000556`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### CommodityTariff (`0x00000700`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### EcosystemInformation (`0x00000750`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### CommissionerControl (`0x00000751`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### JointFabricDatastore (`0x00000752`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### JointFabricAdministrator (`0x00000753`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### TlsCertificateManagement (`0x00000801`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### TlsClientManagement (`0x00000802`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### MeterIdentification (`0x00000B06`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### CommodityMetering (`0x00000B07`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### UnitTesting (`0xFFF1FC05`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### FaultInjection (`0xFFF1FC06`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload

### SampleMei (`0xFFF1FC20`)
- [x] Path decode
- [x] Attribute payload
- [x] Command payload
- [x] Event payload
