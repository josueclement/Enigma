using System.IO;
using System.Threading.Tasks;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Enigma.PublicKey;
using Enigma.Utils;
using Enigma.WpfApp.Views.Dialogs;
using Enigma.Extensions;
using Wpf.Ui;
using Wpf.Ui.Controls;

namespace Enigma.WpfApp.ViewModels.Pages;

public class RsaPageViewModel : ObservableObject
{
    private readonly IContentDialogService _dialogService;
    private readonly IPublicKeyServiceFactory _publicKeyServiceFactory;

    public RsaPageViewModel(IContentDialogService dialogService,
        IPublicKeyServiceFactory publicKeyServiceFactory)
    {
        _dialogService = dialogService;
        _publicKeyServiceFactory = publicKeyServiceFactory;
        GenerateKeyPairCommand = new AsyncRelayCommand(GenerateKeyPairAsync);
    }

    private string? _publicKey;
    public string? PublicKey
    {
        get => _publicKey;
        set => SetProperty(ref _publicKey, value);
    }
    
    private string? _privateKey;
    public string? PrivateKey
    {
        get => _privateKey;
        set => SetProperty(ref _privateKey, value);
    }

    private byte[] _inputData = [];
    public byte[] InputData
    {
        get => _inputData;
        set => SetProperty(ref _inputData, value);
    }
    
    public AsyncRelayCommand GenerateKeyPairCommand { get; }

    private async Task GenerateKeyPairAsync()
    {
        var keyGenerationDialog = new RsaKeyPairGenerationDialog();
        var dialog = new ContentDialog(_dialogService.GetDialogHost())
        {
            Title = "Generate RSA Key Pair",
            Content = keyGenerationDialog,
            PrimaryButtonText = "Generate",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary
        };
        
        Binding primaryButtonBinding = new Binding(nameof(RsaKeyPairGenerationDialog.IsDataValid))
        {
            Source = keyGenerationDialog,
            Mode = BindingMode.OneWay
        };
        dialog.SetBinding(ContentDialog.IsPrimaryButtonEnabledProperty, primaryButtonBinding);
        
        var result = await dialog.ShowAsync();
        if (result == ContentDialogResult.Primary)
        {
            PublicKey = "Please wait...";
            PrivateKey = "Please wait...";
            
            var keySize = keyGenerationDialog.KeySize;

            // await GenerateRsaKeyPairAsync(keySize);
            await Task.Run(async () => await GenerateRsaKeyPairAsync(keySize));
        }
    }

    private async Task GenerateRsaKeyPairAsync(int keySize)
    {
        var rsa = _publicKeyServiceFactory.CreateRsaService();
        var keyPair = rsa.GenerateKeyPair(keySize);
        using var pubMs = new MemoryStream();
        PemUtils.SaveKey(keyPair.Public, pubMs);
        PublicKey = pubMs.ToArray().GetUtf8String();
            
        using var priMs = new MemoryStream();
        PemUtils.SaveKey(keyPair.Private, priMs);
        PrivateKey = priMs.ToArray().GetUtf8String();

        await Task.CompletedTask;
    }
}