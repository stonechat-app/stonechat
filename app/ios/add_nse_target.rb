# Adds the NotificationService app-extension target to Runner.xcodeproj.
# Idempotent: safe to re-run (bails if the target exists). Run with the
# CocoaPods ruby:  cd app/ios && pod ruby? no — plain `ruby add_nse_target.rb`
# (the xcodeproj gem ships with CocoaPods).
require 'xcodeproj'

project = Xcodeproj::Project.open('Runner.xcodeproj')
if project.targets.any? { |t| t.name == 'NotificationService' }
  puts 'NotificationService target already present'
  exit 0
end

runner = project.targets.find { |t| t.name == 'Runner' }
nse = project.new_target(:app_extension, 'NotificationService', :ios, '15.0')

group = project.main_group.new_group('NotificationService', 'NotificationService')
sources = %w[NotificationService.swift StonechatBackend.swift PinnedWebSocket.swift]
sources.each { |f| nse.add_file_references([group.new_reference(f)]) }
group.new_reference('Info.plist')
group.new_reference('NotificationService.entitlements')
group.new_reference('StonechatCore.h')

nse.build_configurations.each do |config|
  # Generated.xcconfig defines FLUTTER_BUILD_NAME/NUMBER so the extension's
  # version always matches the app's (App Store validation requires it).
  config.base_configuration_reference =
    project.files.find { |f| f.path == 'Flutter/Generated.xcconfig' }
  config.build_settings.merge!(
    'PRODUCT_BUNDLE_IDENTIFIER' => 'app.stonechat.mobile.NotificationService',
    'PRODUCT_NAME' => '$(TARGET_NAME)',
    'INFOPLIST_FILE' => 'NotificationService/Info.plist',
    'CODE_SIGN_ENTITLEMENTS' => 'NotificationService/NotificationService.entitlements',
    'SWIFT_VERSION' => '5.0',
    'SWIFT_OBJC_BRIDGING_HEADER' => 'NotificationService/StonechatCore.h',
    'MARKETING_VERSION' => '$(FLUTTER_BUILD_NAME)',
    'CURRENT_PROJECT_VERSION' => '$(FLUTTER_BUILD_NUMBER)',
    'IPHONEOS_DEPLOYMENT_TARGET' => '15.0',
    'TARGETED_DEVICE_FAMILY' => '1,2',
    'CODE_SIGN_STYLE' => 'Automatic',
    'DEVELOPMENT_TEAM' => 'G6D8JHBKSK',
    'GENERATE_INFOPLIST_FILE' => 'NO',
    'SKIP_INSTALL' => 'YES',
    # The protocol core — sessions + KEMs in one staticlib. Direct symbol
    # references keep it; no -force_load needed here.
    'OTHER_LDFLAGS' => ['$(inherited)', '$(PROJECT_DIR)/Core/libstonechat_core.a'],
  )
end

# Embed in Runner ("Embed Foundation Extensions").
embed = runner.build_phases.find do |p|
  p.is_a?(Xcodeproj::Project::Object::PBXCopyFilesBuildPhase) &&
    p.symbol_dst_subfolder_spec == :plug_ins
end
embed ||= runner.new_copy_files_build_phase('Embed Foundation Extensions').tap do |p|
  p.symbol_dst_subfolder_spec = :plug_ins
end
build_file = embed.add_file_reference(nse.product_reference)
build_file.settings = { 'ATTRIBUTES' => ['RemoveHeadersOnCopy'] }
runner.add_dependency(nse)

project.save
puts 'NotificationService target added'
