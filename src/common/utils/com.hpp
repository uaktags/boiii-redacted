#pragma once

#include "nt.hpp"
#include <shlobj.h>
#include <oleauto.h>

#if defined(__has_include) && __has_include(<atlbase.h>)
#include <atlbase.h>
#else
template <typename T> class CComPtr {
public:
  static REFIID interface_id() { return __uuidof(T); }

  CComPtr() : p_(nullptr) {}
  CComPtr(T *p) : p_(p) {
    if (p_)
      p_->AddRef();
  }
  CComPtr(const CComPtr &other) : p_(other.p_) {
    if (p_)
      p_->AddRef();
  }
  CComPtr(CComPtr &&other) noexcept : p_(other.p_) { other.p_ = nullptr; }
  ~CComPtr() {
    if (p_)
      p_->Release();
  }

  CComPtr &operator=(T *p) {
    if (p != p_) {
      if (p_)
        p_->Release();
      p_ = p;
      if (p_)
        p_->AddRef();
    }
    return *this;
  }
  CComPtr &operator=(const CComPtr &other) { return *this = other.p_; }
  CComPtr &operator=(CComPtr &&other) noexcept {
    if (this != &other) {
      if (p_)
        p_->Release();
      p_ = other.p_;
      other.p_ = nullptr;
    }
    return *this;
  }

  T **operator&() {
    if (p_) {
      p_->Release();
      p_ = nullptr;
    }
    return &p_;
  }

  T **get_address_for_query() { return operator&(); }

  template <typename Q> HRESULT QueryInterface(Q **out) const {
    if (!out)
      return E_POINTER;
    if (!p_)
      return E_NOINTERFACE;
    return p_->QueryInterface(__uuidof(Q), reinterpret_cast<void **>(out));
  }

  T *operator->() const { return p_; }
  operator T *() const { return p_; }
  T &operator*() const { return *p_; }
  bool operator!() const { return p_ == nullptr; }
  bool operator==(T *p) const { return p_ == p; }
  bool operator!=(T *p) const { return p_ != p; }

  void Attach(T *p) {
    if (p_)
      p_->Release();
    p_ = p;
  }
  T *Detach() {
    T *tmp = p_;
    p_ = nullptr;
    return tmp;
  }
  void Release() {
    if (p_) {
      p_->Release();
      p_ = nullptr;
    }
  }

private:
  T *p_{nullptr};
};

class CComVariant : public VARIANT {
public:
  CComVariant() noexcept { VariantInit(this); }

  CComVariant(const CComVariant &other) : CComVariant() {
    (void)VariantCopy(this, &other);
  }

  CComVariant(CComVariant &&other) noexcept {
    memcpy(static_cast<VARIANT *>(this), static_cast<const VARIANT *>(&other),
           sizeof(VARIANT));
    VariantInit(&other);
  }

  CComVariant(const VARIANT &other) : CComVariant() {
    (void)VariantCopy(this, &other);
  }

  CComVariant(const char *value) : CComVariant() { assign_string(value); }
  CComVariant(const wchar_t *value) : CComVariant() { assign_string(value); }

  // WebView2 launcher bridge constructs variants from JSON primitives.
  CComVariant(bool value) : CComVariant() {
    vt = VT_BOOL;
    boolVal = value ? VARIANT_TRUE : VARIANT_FALSE;
  }

  CComVariant(int value) : CComVariant() {
    vt = VT_I4;
    lVal = value;
  }

  CComVariant(double value) : CComVariant() {
    vt = VT_R8;
    dblVal = value;
  }

  void Clear() { VariantClear(this); }

  CComVariant &operator=(const CComVariant &other) {
    if (this != &other) {
      VariantClear(this);
      (void)VariantCopy(this, &other);
    }
    return *this;
  }

  CComVariant &operator=(CComVariant &&other) noexcept {
    if (this != &other) {
      VariantClear(this);
      memcpy(static_cast<VARIANT *>(this),
             static_cast<const VARIANT *>(&other), sizeof(VARIANT));
      VariantInit(&other);
    }
    return *this;
  }

  ~CComVariant() { VariantClear(this); }

private:
  void assign_string(const wchar_t *value) {
    vt = VT_BSTR;
    bstrVal = SysAllocString(value ? value : L"");
  }

  void assign_string(const char *value) {
    const char *text = value ? value : "";
    const int length = MultiByteToWideChar(CP_UTF8, 0, text, -1, nullptr, 0);
    if (length <= 0) {
      assign_string(L"");
      return;
    }

    std::wstring wide(static_cast<size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text, -1, wide.data(), length);
    wide.resize(static_cast<size_t>(length - 1));
    assign_string(wide.c_str());
  }
};

class CComBSTR {
public:
  explicit CComBSTR(const wchar_t *value)
      : value_(SysAllocString(value ? value : L"")) {}

  explicit CComBSTR(const char *value) {
    const char *text = value ? value : "";
    const int length =
        MultiByteToWideChar(CP_UTF8, 0, text, -1, nullptr, 0);
    if (length <= 0) {
      value_ = SysAllocString(L"");
      return;
    }

    std::wstring wide(static_cast<size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text, -1, wide.data(), length);
    value_ = SysAllocString(wide.c_str());
  }

  CComBSTR(const CComBSTR &) = delete;
  CComBSTR &operator=(const CComBSTR &) = delete;

  ~CComBSTR() { SysFreeString(value_); }

  operator BSTR() const { return value_; }

private:
  BSTR value_{nullptr};
};

class CComSafeArrayBound {
public:
  void SetCount(const ULONG count) { bound_.cElements = count; }
  void SetLowerBound(const LONG lower_bound) { bound_.lLbound = lower_bound; }
  const SAFEARRAYBOUND &get() const { return bound_; }

private:
  SAFEARRAYBOUND bound_{};
};

template <typename T> class CComSafeArray {
public:
  CComSafeArray(const CComSafeArrayBound *bounds, const UINT count)
      : array_(create_array(bounds, count)) {}

  ~CComSafeArray() {
    if (array_)
      SafeArrayDestroy(array_);
  }

  class element {
  public:
    element(SAFEARRAY *array, const LONG index) : array_(array), index_(index) {}

    element &operator=(const VARIANT &value) {
      VARIANT copy{};
      VariantInit(&copy);
      (void)VariantCopy(&copy, &value);
      (void)SafeArrayPutElement(array_, &index_, &copy);
      VariantClear(&copy);
      return *this;
    }

  private:
    SAFEARRAY *array_;
    LONG index_;
  };

  element operator[](const LONG index) { return element(array_, index); }
  operator SAFEARRAY *() const { return array_; }

private:
  static SAFEARRAY *create_array(const CComSafeArrayBound *bounds,
                                 const UINT count) {
    SAFEARRAYBOUND bound = bounds->get();
    return SafeArrayCreate(VT_VARIANT, count, &bound);
  }

  SAFEARRAY *array_;
};

class CComDispatchDriver : public CComPtr<IDispatch> {
public:
  HRESULT Invoke1(const DISPID dispid, VARIANT *argument,
                 VARIANT *result) const {
    if (!this->operator->())
      return E_POINTER;

    DISPPARAMS params{argument, nullptr, 1, 0};
    return this->operator->()->Invoke(
        dispid, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD, &params,
        result, nullptr, nullptr);
  }
};
#endif

namespace utils::com {
bool select_folder(std::string &out_folder,
                   const std::string &title = "Select a Folder",
                   const std::string &selected_folder = {});
CComPtr<IProgressDialog> create_progress_dialog();
} // namespace utils::com
