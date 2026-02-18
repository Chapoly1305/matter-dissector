# Cluster Completion TODO (Matter v1.5)

Generated at: `2026-02-18 23:36 UTC`

## Scope
- Source baseline: `connectedhomeip v1.5-branch`
- Tracking target: `ws-4.6.3` full IM/cluster parsing completion

## Global Status
- [x] Full cluster/attribute/command/event ID-to-name mapping in IM paths

## Per-Cluster Checklist
Legend:
- `Path decode`: Cluster/Attribute/Command/Event path IDs decoded to names
- `Attribute payload`: Attribute data/status payload fields decoded structurally
- `Command payload`: Command request/response payload fields decoded structurally
- `Event payload`: Event payload fields decoded structurally

### Identify (`0x00000003`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### Groups (`0x00000004`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### OnOff (`0x00000006`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### LevelControl (`0x00000008`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### PulseWidthModulation (`0x0000001C`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### Descriptor (`0x0000001D`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### Binding (`0x0000001E`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### AccessControl (`0x0000001F`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### Actions (`0x00000025`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### BasicInformation (`0x00000028`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### OtaSoftwareUpdateProvider (`0x00000029`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### OtaSoftwareUpdateRequestor (`0x0000002A`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### LocalizationConfiguration (`0x0000002B`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### TimeFormatLocalization (`0x0000002C`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### UnitLocalization (`0x0000002D`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### PowerSourceConfiguration (`0x0000002E`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### PowerSource (`0x0000002F`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### GeneralCommissioning (`0x00000030`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### NetworkCommissioning (`0x00000031`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### DiagnosticLogs (`0x00000032`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### GeneralDiagnostics (`0x00000033`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### SoftwareDiagnostics (`0x00000034`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### ThreadNetworkDiagnostics (`0x00000035`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### WiFiNetworkDiagnostics (`0x00000036`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### EthernetNetworkDiagnostics (`0x00000037`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### TimeSynchronization (`0x00000038`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### BridgedDeviceBasicInformation (`0x00000039`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### Switch (`0x0000003B`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### AdministratorCommissioning (`0x0000003C`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### OperationalCredentials (`0x0000003E`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### GroupKeyManagement (`0x0000003F`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### FixedLabel (`0x00000040`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### UserLabel (`0x00000041`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### ProxyConfiguration (`0x00000042`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### ProxyDiscovery (`0x00000043`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### ProxyValid (`0x00000044`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### BooleanState (`0x00000045`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### IcdManagement (`0x00000046`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### Timer (`0x00000047`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### OvenCavityOperationalState (`0x00000048`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### OvenMode (`0x00000049`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### LaundryDryerControls (`0x0000004A`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### ModeSelect (`0x00000050`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### LaundryWasherMode (`0x00000051`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### RefrigeratorAndTemperatureControlledCabinetMode (`0x00000052`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### LaundryWasherControls (`0x00000053`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### RvcRunMode (`0x00000054`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### RvcCleanMode (`0x00000055`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### TemperatureControl (`0x00000056`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### RefrigeratorAlarm (`0x00000057`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### DishwasherMode (`0x00000059`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### AirQuality (`0x0000005B`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### SmokeCoAlarm (`0x0000005C`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### DishwasherAlarm (`0x0000005D`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### MicrowaveOvenMode (`0x0000005E`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### MicrowaveOvenControl (`0x0000005F`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### OperationalState (`0x00000060`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### RvcOperationalState (`0x00000061`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### ScenesManagement (`0x00000062`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### Groupcast (`0x00000065`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### HepaFilterMonitoring (`0x00000071`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### ActivatedCarbonFilterMonitoring (`0x00000072`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### WaterTankLevelMonitoring (`0x00000079`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### BooleanStateConfiguration (`0x00000080`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### ValveConfigurationAndControl (`0x00000081`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### ElectricalPowerMeasurement (`0x00000090`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### ElectricalEnergyMeasurement (`0x00000091`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### WaterHeaterManagement (`0x00000094`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### CommodityPrice (`0x00000095`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### Messages (`0x00000097`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### DeviceEnergyManagement (`0x00000098`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### EnergyEvse (`0x00000099`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### EnergyPreference (`0x0000009B`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### PowerTopology (`0x0000009C`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### EnergyEvseMode (`0x0000009D`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### WaterHeaterMode (`0x0000009E`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### DeviceEnergyManagementMode (`0x0000009F`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### ElectricalGridConditions (`0x000000A0`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### DoorLock (`0x00000101`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### WindowCovering (`0x00000102`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### ClosureControl (`0x00000104`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### ClosureDimension (`0x00000105`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### ServiceArea (`0x00000150`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### PumpConfigurationAndControl (`0x00000200`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### Thermostat (`0x00000201`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### FanControl (`0x00000202`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### ThermostatUserInterfaceConfiguration (`0x00000204`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### ColorControl (`0x00000300`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### BallastConfiguration (`0x00000301`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### IlluminanceMeasurement (`0x00000400`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### TemperatureMeasurement (`0x00000402`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### PressureMeasurement (`0x00000403`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### FlowMeasurement (`0x00000404`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### RelativeHumidityMeasurement (`0x00000405`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### OccupancySensing (`0x00000406`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### CarbonMonoxideConcentrationMeasurement (`0x0000040C`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### CarbonDioxideConcentrationMeasurement (`0x0000040D`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### NitrogenDioxideConcentrationMeasurement (`0x00000413`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### OzoneConcentrationMeasurement (`0x00000415`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### Pm25ConcentrationMeasurement (`0x0000042A`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### FormaldehydeConcentrationMeasurement (`0x0000042B`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### Pm1ConcentrationMeasurement (`0x0000042C`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### Pm10ConcentrationMeasurement (`0x0000042D`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### TotalVolatileOrganicCompoundsConcentrationMeasurement (`0x0000042E`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### RadonConcentrationMeasurement (`0x0000042F`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### SoilMeasurement (`0x00000430`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### WiFiNetworkManagement (`0x00000451`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### ThreadBorderRouterManagement (`0x00000452`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### ThreadNetworkDirectory (`0x00000453`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### WakeOnLan (`0x00000503`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### Channel (`0x00000504`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### TargetNavigator (`0x00000505`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### MediaPlayback (`0x00000506`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### MediaInput (`0x00000507`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### LowPower (`0x00000508`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### KeypadInput (`0x00000509`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### ContentLauncher (`0x0000050A`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### AudioOutput (`0x0000050B`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### ApplicationLauncher (`0x0000050C`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### ApplicationBasic (`0x0000050D`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### AccountLogin (`0x0000050E`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### ContentControl (`0x0000050F`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### ContentAppObserver (`0x00000510`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### ZoneManagement (`0x00000550`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### CameraAvStreamManagement (`0x00000551`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### CameraAvSettingsUserLevelManagement (`0x00000552`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### WebRTCTransportProvider (`0x00000553`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### WebRTCTransportRequestor (`0x00000554`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### PushAvStreamTransport (`0x00000555`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### Chime (`0x00000556`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### CommodityTariff (`0x00000700`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### EcosystemInformation (`0x00000750`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### CommissionerControl (`0x00000751`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### JointFabricDatastore (`0x00000752`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### JointFabricAdministrator (`0x00000753`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### TlsCertificateManagement (`0x00000801`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### TlsClientManagement (`0x00000802`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### MeterIdentification (`0x00000B06`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### CommodityMetering (`0x00000B07`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### UnitTesting (`0xFFF1FC05`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### FaultInjection (`0xFFF1FC06`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload

### SampleMei (`0xFFF1FC20`)
- [x] Path decode
- [ ] Attribute payload
- [ ] Command payload
- [ ] Event payload
